use std::sync::Arc;

use bytemuck::{Pod, Zeroable};
use tracing::instrument;

use crate::arp::handle_arp;
use crate::error::Result;
use crate::ip::{IP_HDR_MAXSIZE, IP_HDR_MINSIZE, IP_hdr, handle_ip_frame};
use crate::tcp::{
    PseudoHdr, TCP_HDR_MAXSIZE, TCP_HDR_MINSIZE, TCP_PSEUDOHDR_SIZE, hdr::TCP_hdr, opts::TCP_opts,
};
use crate::tcup::TCup;
use crate::types::{MAC, MockHost};
use crate::utils::{calc_checksum_be, mac_to_str};

/*
#define ETH_ALEN	6		        /* Octets in one ethernet addr	 */
#define ETH_HLEN	14		        /* Total octets in header.	 */
#define ETH_ZLEN	60		        /* Min. octets in frame sans FCS */
#define ETH_DATA_LEN	1500		/* Max. octets in payload	 */
#define ETH_FRAME_LEN	1514		/* Max. octets in frame sans FCS */
#define ETH_FCS_LEN	4		        /* Octets in the FCS		 */
 */

const FCS_SIZE: usize = 4;
const MAC_ADDR_LEN: usize = 6;
pub const ETH_FRAME_MIN_SIZE: usize = ETH_HDR_SIZE + ETH_PAY_MIN_SIZE; // min size sans FCS
pub const ETH_FRAME_MAX_SIZE: usize = ETH_PAY_MAX_SIZE + ETH_HDR_SIZE; // max size sans FCS
pub const ETH_HDR_SIZE: usize = 14;
pub const ETH_PAY_MIN_SIZE: usize = 46;
pub const ETH_PAY_MAX_SIZE: usize = 1500; // maximum payload size for a single frame (MTU)

// ethernet header types (prot_type) big endian
// EtherType fields (IEEE 802 numbers)
pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86DD;
pub const ETH_P_ARP: u16 = 0x0806;

// offsets
const ETH_PAY_OFFSET: usize = ETH_HDR_SIZE;

const IP_HDR_OFFSET: usize = ETH_HDR_SIZE;
const IP_CHECK_OFFSET: usize = ETH_HDR_SIZE + 10;
/// minimum offset
const IP_PAY_OFFSET: usize = ETH_HDR_SIZE + IP_HDR_MINSIZE;

const TCP_HDR_OFFSET: usize = ETH_HDR_SIZE + IP_HDR_MINSIZE;
const TCP_CHECK_OFFSET_FROM_HDR: usize = 16;
/// minimum offset
const TCP_PAY_OFFSET: usize = ETH_HDR_SIZE + IP_HDR_MINSIZE + TCP_HDR_MINSIZE;

#[derive(Debug, Default, Clone)]
pub struct EthFrame {
    // network order bytes
    pub data: Vec<u8>,
}

impl EthFrame {
    pub fn new(data: &[u8]) -> Result<Self> {
        if data.len() > ETH_FRAME_MAX_SIZE {
            return Err("data exceeds MTU".into());
        }

        if data.len() < ETH_HDR_SIZE {
            return Err("data below minimum eth hdr size".into());
        }

        Ok(EthFrame {
            data: Vec::from(data),
        })
    }

    pub fn with_cap(cap: usize) -> Result<Self> {
        if cap > ETH_FRAME_MAX_SIZE {
            return Err("data exceeds MTU".into());
        }

        if cap < ETH_HDR_SIZE {
            return Err("data below minimum eth hdr size".into());
        }

        Ok(EthFrame {
            data: Vec::with_capacity(cap),
        })
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.data.as_slice()
    }

    fn iphdr_size(&self) -> usize {
        ((self.data[ETH_HDR_SIZE] & 0x0F) << 2) as usize
    }

    fn tcphdr_size(&self) -> usize {
        let ip_hdr_size = self.iphdr_size();
        ((self.data[ETH_HDR_SIZE + ip_hdr_size] >> 4) << 2) as usize
    }

    pub fn get_eth_hdr(&self) -> Eth_hdr {
        Eth_hdr::from_be_bytes(
            self.data[..ETH_HDR_SIZE]
                .try_into()
                .expect("we never have a frame without a header"),
        )
    }

    pub fn set_eth_hdr(&mut self, hdr: Eth_hdr) {
        self.data.as_mut_slice()[..ETH_HDR_SIZE].copy_from_slice(&hdr.into_be_bytes());
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
        assert_eq!(hdr.len(), IP_HDR_MAXSIZE);

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
        let lo = ETH_HDR_SIZE + self.iphdr_size();
        let hi = lo + TCP_HDR_MINSIZE;

        if self.data.len() < hi {
            return Err("frame data too small to write TCP header".into());
        }

        assert!(hdr.len() <= TCP_HDR_MAXSIZE);

        self.data.as_mut_slice()[lo..hi].copy_from_slice(&hdr.into_be_bytes());

        Ok(())
    }

    /// sets the TCP checksum, needs to be called after setting the ip payload!
    pub fn set_tcp_check(&mut self, phdr: PseudoHdr) -> Result<()> {
        // set TCP check to 0
        let check_off = ETH_HDR_SIZE + self.iphdr_size() + TCP_CHECK_OFFSET_FROM_HDR;
        self.data[check_off] = 0;
        self.data[check_off + 1] = 0;

        // populate buffer for checksum calculation
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

        Ok(())
    }

    fn get_tcp_opt(&self) -> Result<Option<TCP_opts>> {
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
        let offset = ETH_HDR_SIZE + self.iphdr_size() + self.tcphdr_size();

        if offset > self.data.len() {
            return Err("frame data is too small for requested TCP payload".into());
        }

        Ok(&self.data.as_slice()[offset..])
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
}

#[derive(Debug, Default, Pod, Zeroable, Clone, Copy)]
#[repr(C, packed)]
pub struct Eth_hdr {
    pub dmac: [u8; MAC_ADDR_LEN], // dest MAC address
    pub smac: [u8; MAC_ADDR_LEN], // src MAC address
    pub prot_type: u16,
}

impl std::fmt::Display for Eth_hdr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let dest_mac = mac_to_str(&self.dmac);
        let source_mac = mac_to_str(&self.smac);
        let hrd_type = match self.prot_type {
            ETH_P_IP => String::from("IPV4"),
            ETH_P_IPV6 => String::from("IPV6"),
            ETH_P_ARP => String::from("ARP"),
            n => n.to_string(),
        };

        write!(
            f,
            "\n{:<12} {:>17}\n{:<12} {:>17}\n{:<12} {:>17}",
            "dest MAC", dest_mac, "source MAC", source_mac, "type", hrd_type
        )
    }
}

impl Eth_hdr {
    pub fn new(dmac: MAC, smac: MAC, eth_type: u16) -> Self {
        Eth_hdr {
            dmac: dmac.octets(),
            smac: smac.octets(),
            prot_type: eth_type,
        }
    }
    /// from network order bytes
    pub fn from_be_bytes(buf: &[u8; ETH_HDR_SIZE]) -> Self {
        let mut hdr: Eth_hdr = bytemuck::cast(*buf);
        hdr.prot_type = u16::from_be(hdr.prot_type);
        hdr
    }

    /// into network order bytes
    pub fn into_be_bytes(mut self) -> [u8; ETH_HDR_SIZE] {
        self.prot_type = u16::to_be(self.prot_type);
        bytemuck::cast(self)
    }
}

#[instrument(skip_all, err)]
pub async fn handle_frame(inc: EthFrame, tcup: Arc<TCup>, host: &mut MockHost) -> Result<()> {
    let hdr = inc.get_eth_hdr();
    println!("{}", hdr);

    // TODO: discard incoming frame if its not directed at us

    match hdr.prot_type {
        ETH_P_IP => {
            handle_ip_frame(inc, tcup, host).await?;
        }
        ETH_P_ARP => {
            handle_arp(inc, tcup, host).await?;
        }
        ETH_P_IPV6 => (),
        _ => return Err("unsupported frame type".into()),
    };

    Ok(())
}
