use std::net::Ipv4Addr;

use num_enum::TryFromPrimitive;
use zerocopy::{BE, FromBytes, Immutable, IntoBytes, KnownLayout, U16};

use super::mac::*;
use crate::eth::EthArp;
use crate::eth::error::EthErr;
use crate::ip::{IP_HDR_MAXSIZE, IP_HDR_MINSIZE, IP_hdr, IpPacket};
use crate::tcp::TCP_OPT_MAX_SIZE;
use crate::tcp::{
    TCP_HDR_MAXSIZE, TCP_HDR_MINSIZE, TCP_PSEUDOHDR_SIZE, hdr::PseudoHdr, hdr::TCP_hdr,
    opts::TCP_opts,
};
use crate::types::TCPCon;
use crate::utils::calc_checksum_be;

/*
#define ETH_ALEN	6		        /* Octets in one ethernet addr	 */
#define ETH_HLEN	14		        /* Total octets in header.	 */
#define ETH_ZLEN	60		        /* Min. octets in frame sans FCS */
#define ETH_DATA_LEN	1500		/* Max. octets in payload	 */
#define ETH_FRAME_LEN	1514		/* Max. octets in frame sans FCS */
#define ETH_FCS_LEN	4		        /* Octets in the FCS		 */
 */

/// bytes in FCS
pub const FCS_SIZE: usize = libc::ETH_FCS_LEN as usize;
/// min num of bytes in frame
pub const ETH_FRAME_MIN_SIZE: usize = libc::ETH_ZLEN as usize;
/// max size sans FCS
pub const ETH_FRAME_MAX_SIZE: usize = libc::ETH_FRAME_LEN as usize;

pub const ETH_HDR_SIZE: usize = libc::ETH_HLEN as usize;
pub const ETH_PAY_MIN_SIZE: usize = ETH_FRAME_MIN_SIZE - ETH_HDR_SIZE;
/// maximum payload size for a single frame
pub const ETH_PAY_MAX_SIZE: usize = libc::ETH_DATA_LEN as usize;

/// Ethernet header types (prot_type) big endian
/// EtherType fields (IEEE 802 numbers)
///
/// Only these protocols are supported
#[derive(TryFromPrimitive, PartialEq, Clone, Copy, Debug)]
#[repr(u16)]
pub enum EthProt {
    Ip = libc::ETH_P_IP as u16,
    Arp = libc::ETH_P_ARP as u16,
    // Ipv6 = libc::ETH_P_IPV6 as u16,
}

/*
    offsets
*/
const ETH_PAY_OFFSET: usize = ETH_HDR_SIZE;

const IP_HDR_OFFSET: usize = ETH_HDR_SIZE;
const IP_CHECK_OFFSET: usize = ETH_HDR_SIZE + 10;
/// minimum offset
const IP_PAY_OFFSET: usize = ETH_HDR_SIZE + IP_HDR_MINSIZE;

const TCP_HDR_OFFSET: usize = ETH_HDR_SIZE + IP_HDR_MINSIZE;
const TCP_CHECK_OFFSET_FROM_HDR: usize = 16;
pub const TCP_HDR_DOF_OFF: usize = 12;
/// minimum offset
const TCP_PAY_OFFSET: usize = ETH_HDR_SIZE + IP_HDR_MINSIZE + TCP_HDR_MINSIZE;

// when parsing between network layers we reuse the underlying buffer but change the type
#[derive(Debug, Default, Clone)]
pub struct EthFrame(Vec<u8>);

pub enum EthFramePayload {
    Arp(EthArp),
    Ip(IpPacket),
}

impl EthFrame {
    pub fn parse(data: impl Into<Vec<u8>>) -> Result<EthFrame, EthErr> {
        let data = data.into();

        if data.len() > ETH_FRAME_MAX_SIZE {
            return Err(EthErr::ParseError("data exceeds MTU size"));
        }

        if data.len() < ETH_HDR_SIZE {
            return Err(EthErr::ParseError("data below minimumt hdr size"));
        }

        let hdr = Eth_hdr::read_from_prefix(&data)
            .expect("a parsed frame has sufficient len")
            .0;

        let _: EthProt = hdr
            .prot_type
            .get()
            .try_into()
            .map_err(|_| EthErr::InvalidProtError)?;

        Ok(EthFrame(data))
    }

    pub fn into_parts(self) -> (Eth_hdr, EthFramePayload) {
        let hdr = self.hdr().clone();

        let pay = match self.prot() {
            EthProt::Ip => EthFramePayload::Ip(self.0.into()),
            EthProt::Arp => EthFramePayload::Arp(self.0.into()),
        };

        (hdr, pay)
    }

    pub fn prot(&self) -> EthProt {
        u16::from_be_bytes(
            self.data[MAC_ADDR_LEN * 2..MAC_ADDR_LEN * 2 + 2]
                .try_into()
                .unwrap(),
        )
        .try_into()
        .expect("unable to read a support prot from eth frame")
    }

    fn with_cap(cap: usize) -> Result<Self> {
        if cap == 0 {
            return Err("capacity cant be zero".into());
        }
        if cap > ETH_FRAME_MAX_SIZE {
            return Err("data exceeds MTU".into());
        }
        if cap < ETH_HDR_SIZE {
            return Err("data below minimum eth hdr size".into());
        }

        Ok(EthFrame {
            data: vec![0u8; cap],
        })
    }

    pub fn new_tcp(
        eth_hdr: Eth_hdr,
        ip_hdr: IP_hdr,
        tcp_hdr: TCP_hdr,
        tcp_opts: TCP_opts,
        tcp_pay: &[u8],
    ) -> Result<Self> {
        let mut packet = EthFrame::with_cap(ETH_HDR_SIZE + ip_hdr.tot_len as usize)?;

        packet.set_eth_hdr(&eth_hdr);
        packet.set_ip_hdr(ip_hdr)?;
        packet.set_tcp_hdr(tcp_hdr)?;
        packet.set_tcp_opts(tcp_opts)?;
        packet.set_tcp_pay(tcp_pay)?;
        packet.set_tcp_check(PseudoHdr::new(
            ip_hdr.src_addr,
            ip_hdr.dest_addr,
            tcp_hdr.len() + tcp_pay.len(),
        ))?;
        packet.set_ip_check()?;

        if packet.data.len() != ETH_HDR_SIZE + ip_hdr.len() + tcp_hdr.len() {
            return Err("error when assembling frame: lengths dont match".into());
        }

        Ok(packet)
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.data.as_slice()
    }

    fn iphdr_size(&self) -> usize {
        let res = ((self.data[ETH_HDR_SIZE] & 0x0F) << 2) as usize;
        assert!((IP_HDR_MINSIZE..=IP_HDR_MAXSIZE).contains(&res));
        res
    }

    fn tcphdr_size(&self) -> usize {
        let offset = ETH_HDR_SIZE + self.iphdr_size() + TCP_HDR_DOF_OFF;
        let res = (((self.data[offset] >> 4) & 0xF) << 2) as usize;
        assert!((TCP_HDR_MINSIZE..=TCP_HDR_MAXSIZE).contains(&res));
        res
    }

    pub fn hdr(&self) -> &Eth_hdr {
        Eth_hdr::ref_from_prefix(&self.data)
            .expect("a parsed frame has sufficient len")
            .0
        // Eth_hdr::from_be_bytes(
        //     self.data[..ETH_HDR_SIZE]
        //         .try_into()
        //         .expect("we never have a frame without a header"),
        // )
    }

    pub fn set_eth_hdr(&mut self, hdr: &Eth_hdr) {
        hdr.as_bytes()
            .write_to_prefix(self.data.as_mut_slice())
            .expect("parsed frame has sufficient len");
        // self.data.as_mut_slice()[..ETH_HDR_SIZE].copy_from_slice(&hdr.into_be_bytes());
    }

    pub fn get_eth_pay(&self) -> &[u8] {
        &self.data.as_slice()[ETH_PAY_OFFSET..]
    }

    pub fn get_eth_pay_mut(&mut self) -> Result<&mut [u8]> {
        if self.len() < ETH_PAY_OFFSET {
            return Err("no ETH payload found".into());
        }

        Ok(&mut self.data.as_mut_slice()[ETH_PAY_OFFSET..])
    }

    pub fn set_eth_pay(&mut self, data: &[u8]) -> Result<()> {
        if ETH_PAY_OFFSET + data.len() > ETH_FRAME_MAX_SIZE {
            return Err("data exceeds MTU".into());
        }

        self.data.truncate(ETH_HDR_SIZE);
        self.data.extend_from_slice(data);

        Ok(())
    }

    pub fn get_ip_hdr(&self) -> Result<IP_hdr> {
        if self.data.len() < IP_HDR_OFFSET + IP_HDR_MINSIZE {
            return Err("not enough data to retrieve IP header".into());
        }

        Ok(IP_hdr::from_be_bytes(
            self.data[IP_HDR_OFFSET..IP_HDR_OFFSET + IP_HDR_MINSIZE].try_into()?,
        ))
    }

    pub fn set_ip_hdr(&mut self, hdr: IP_hdr) -> Result<()> {
        let lo = IP_HDR_OFFSET;
        let hi = IP_HDR_OFFSET + IP_HDR_MINSIZE;

        if self.data.len() < hi {
            return Err("data too small to write IP hdr".into());
        }

        // currently doesnt support IP options
        assert_eq!(
            hdr.len(),
            IP_HDR_MINSIZE,
            "ip options arent supported currently"
        );

        self.data.as_mut_slice()[lo..hi].copy_from_slice(&hdr.into_be_bytes());

        Ok(())
    }

    pub fn set_ip_check(&mut self) -> Result<()> {
        if self.len() < IP_CHECK_OFFSET + 1 {
            return Err("cant set ip checksum, len is too small".into());
        }

        let offset = IP_CHECK_OFFSET;

        // setting to 0 before calculation
        self.data[offset] = 0;
        self.data[offset + 1] = 0;

        let check = calc_checksum_be(&self.data[ETH_HDR_SIZE..ETH_HDR_SIZE + self.iphdr_size()]);
        self.data[offset..offset + size_of::<u16>()].copy_from_slice(&u16::to_be_bytes(check));

        assert_eq!(
            0,
            calc_checksum_be(&self.data[ETH_HDR_SIZE..ETH_HDR_SIZE + self.iphdr_size()]),
            "checksum failed"
        );

        Ok(())
    }

    pub fn get_ip_pay(&self) -> Result<&[u8]> {
        let offset = ETH_HDR_SIZE + self.iphdr_size();

        if self.len() < offset {
            return Err("no IP payload found".into());
        }

        Ok(&self.data.as_slice()[offset..])
    }

    pub fn get_ip_pay_mut(&mut self) -> Result<&mut [u8]> {
        let offset = ETH_HDR_SIZE + self.iphdr_size();
        if self.len() < offset {
            return Err("no IP payload found".into());
        }

        Ok(&mut self.data.as_mut_slice()[offset..])
    }

    /// overwrites the IP payload of the frame with data
    pub fn set_ip_pay(&mut self, data: &[u8]) -> Result<()> {
        let offset = ETH_HDR_SIZE + self.iphdr_size();

        if offset + data.len() > ETH_FRAME_MAX_SIZE {
            return Err("data exceeds MTU".into());
        }

        self.data.truncate(offset);
        self.data.extend_from_slice(data);

        Ok(())
    }

    pub fn get_tcp_hdr(&self) -> Result<TCP_hdr> {
        let lo = ETH_HDR_SIZE + self.iphdr_size();
        let hi = lo + TCP_HDR_MINSIZE;

        if self.data.len() < hi {
            return Err("not enough data to retrieve TCP header".into());
        }

        Ok(TCP_hdr::from_be_bytes(self.data[lo..hi].try_into()?))
    }

    pub fn set_tcp_hdr(&mut self, hdr: TCP_hdr) -> Result<()> {
        if !(TCP_HDR_MINSIZE..=TCP_HDR_MAXSIZE).contains(&hdr.len()) {
            return Err("invalid TCP hdr size".into());
        }

        let lo = ETH_HDR_SIZE + self.iphdr_size();
        let hi = lo + TCP_HDR_MINSIZE;

        if self.data.len() < hi {
            return Err("frame data too small to write TCP header".into());
        }

        self.data.as_mut_slice()[lo..hi].copy_from_slice(&hdr.into_be_bytes());

        assert_eq!(hdr.len(), self.tcphdr_size());
        Ok(())
    }

    pub fn get_tcp_opts(&self) -> Result<TCP_opts> {
        let lo = ETH_HDR_SIZE + self.iphdr_size() + TCP_HDR_MINSIZE;
        let hi = lo + self.tcphdr_size() - TCP_HDR_MINSIZE;

        if self.data.len() < hi {
            return Err("frame data too small to retrieve TCP opts".into());
        }

        TCP_opts::from_be_bytes(&self.data[lo..hi])
    }

    pub fn set_tcp_opts(&mut self, opts: TCP_opts) -> Result<()> {
        let opts = opts.into_be_bytes();
        let lo = ETH_HDR_SIZE + self.iphdr_size() + TCP_HDR_MINSIZE;
        let hi = lo + opts.len();

        if self.data.len() < hi {
            return Err(format!(
                "frame is too small to hold TCP opts: data.len: {}, opt.len: {}",
                self.len(),
                opts.len()
            )
            .into());
        }

        assert!(
            opts.len() <= TCP_OPT_MAX_SIZE,
            "tcp options cant exceed opt max size"
        );

        self.data.as_mut_slice()[lo..hi].copy_from_slice(&opts);

        assert_eq!(self.tcphdr_size(), opts.len() + TCP_HDR_MINSIZE);
        Ok(())
    }

    /// sets the TCP checksum, needs to be called after setting the ip payload!
    pub fn set_tcp_check(&mut self, phdr: PseudoHdr) -> Result<()> {
        // set TCP check to 0
        let check_off = ETH_HDR_SIZE + self.iphdr_size() + TCP_CHECK_OFFSET_FROM_HDR;
        self.data[check_off] = 0;
        self.data[check_off + 1] = 0;

        // populate buffer for checksum calculation
        // TODO: account for IP hdr options
        let mut buf = [0u8; ETH_PAY_MAX_SIZE - IP_HDR_MINSIZE + TCP_PSEUDOHDR_SIZE];
        let mut buf_off = 0;

        buf[..TCP_PSEUDOHDR_SIZE].copy_from_slice(&phdr.into_be_bytes());
        buf_off += TCP_PSEUDOHDR_SIZE;

        let ip_pay = self.get_ip_pay()?;

        if buf.len() < TCP_PSEUDOHDR_SIZE + ip_pay.len() {
            return Err("intermediate checksum buffer cant hold payload".into());
        }

        buf[buf_off..buf_off + ip_pay.len()].copy_from_slice(ip_pay);
        buf_off += ip_pay.len();

        let check = calc_checksum_be(&buf[..buf_off]);
        self.data[check_off..check_off + size_of::<u16>()].copy_from_slice(&check.to_be_bytes());

        // for debug purposes only:
        // writing into the buffer for check
        let ctrl_off = TCP_PSEUDOHDR_SIZE + TCP_CHECK_OFFSET_FROM_HDR;
        buf[ctrl_off..ctrl_off + size_of::<u16>()].copy_from_slice(&check.to_be_bytes());
        debug_assert_eq!(0, calc_checksum_be(&buf[..buf_off]));

        Ok(())
    }

    pub fn get_tcp_opt(&self) -> Result<Option<TCP_opts>> {
        let tcphdr_size = self.tcphdr_size();
        if tcphdr_size < TCP_HDR_MINSIZE {
            return Err("frame doesnt hold TCP header".into());
        }

        let opt_size = tcphdr_size - TCP_HDR_MINSIZE;

        if opt_size == 0 {
            return Ok(None);
        }

        let lo = ETH_HDR_SIZE + self.iphdr_size() + TCP_HDR_MINSIZE;
        let hi = lo + opt_size;

        if self.len() < lo || self.len() < hi {
            return Err("frame is too small for TCP options".into());
        }

        let opt_slice = &self.data[lo..hi];

        TCP_opts::from_be_bytes(opt_slice).map(Option::Some)
    }

    pub fn get_tcp_pay(&self) -> Result<&[u8]> {
        let ip_hdr = self.get_ip_hdr()?;

        let lo = ETH_HDR_SIZE + self.iphdr_size() + self.tcphdr_size();
        let hi = lo + ip_hdr.tot_len as usize - self.iphdr_size() - self.tcphdr_size();

        if lo > self.data.len() || hi > self.data.len() {
            return Err("frame data is too small for requested TCP payload".into());
        }

        Ok(&self.data.as_slice()[lo..hi])
    }

    /// overwrites the TCP payload with data
    pub fn set_tcp_pay(&mut self, data: &[u8]) -> Result<()> {
        let offset = ETH_HDR_SIZE + self.iphdr_size() + self.tcphdr_size();

        if offset + data.len() > ETH_FRAME_MAX_SIZE {
            return Err("data exceeds MTU".into());
        }

        self.data.truncate(offset);
        self.data.extend_from_slice(data);

        Ok(())
    }

    pub fn get_con(&self) -> Result<TCPCon> {
        let ip_hdr = self.get_ip_hdr()?;
        let tcp_hdr = self.get_tcp_hdr()?;

        let con = TCPCon {
            remote_ip: Ipv4Addr::from_octets(ip_hdr.src_addr),
            remote_port: tcp_hdr.sport,
            local_ip: Ipv4Addr::from_octets(ip_hdr.dest_addr),
            local_port: tcp_hdr.dport,
        };
        Ok(con)
    }
}

#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct Eth_hdr {
    pub dmac: [u8; MAC_ADDR_LEN], // dest MAC address
    pub smac: [u8; MAC_ADDR_LEN], // src MAC address
    pub prot_type: U16<BE>,
}

impl std::fmt::Display for Eth_hdr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let dest_mac = Mac::from_octets(self.dmac);
        let source_mac = Mac::from_octets(self.smac);

        let hrd_type = match self.prot_type.get() as i32 {
            libc::ETH_P_IP => String::from("IPV4"),
            libc::ETH_P_IPV6 => String::from("IPV6"),
            libc::ETH_P_ARP => String::from("ARP"),
            n => n.to_string(),
        };

        write!(
            f,
            "dmac: {}, smac: {}, typer: {}",
            dest_mac, source_mac, hrd_type
        )
    }
}

impl Eth_hdr {
    pub fn new(dmac: impl Into<Mac>, smac: impl Into<Mac>, prot_type: EthProt) -> Self {
        Eth_hdr {
            dmac: dmac.into().octets(),
            smac: smac.into().octets(),
            prot_type: zerocopy::U16::<BE>::new(prot_type as u16),
        }
    }
}

// #[instrument(skip_all, err)]
// pub async fn handle_frame(inc: EthFrame, tcup: TCup) -> Result<()> {
//     let hdr = inc.get_eth_hdr();
//     debug!("handling eth {}", hdr);
//
//     // TODO: handle ip datagrams not directed at us
//
//     match hdr.prot_type {
//         ETH_P_IP => {
//             handle_ip_frame(inc, tcup).await?;
//         }
//         ETH_P_ARP => {
//             handle_arp(inc, tcup).await?;
//         }
//         ETH_P_IPV6 => (),
//         _ => {
//             warn!("IpV6 is not supported, dropping frame");
//             return Ok(());
//         }
//     };
//
//     Ok(())
// }
