//Internet Control Message Protocol (ICMP)

use std::net::Ipv4Addr;

use num_enum::TryFromPrimitive;
use tracing::{debug, trace};
use zerocopy::{BE, FromBytes, Immutable, IntoBytes, KnownLayout, U16};

use crate::eth::ETH_HDR_SIZE;
use crate::ip::IpErr::ICMPError;
use crate::ip::{IP_HDR_MINSIZE, IpErr};
use crate::utils::calc_checksum_be;
use crate::utils::packet::{ICMP, IP, Packet, PacketBuf};

const TYPE_ECHO_REPLY: u8 = 0;
const TYPE_ECHO_REQ: u8 = 8;
const TYPE_ECHO_UNREACHABLE: u8 = 3;

const CODE_NET_UNREACHABLE: u8 = 0;
const ICMP_HDR_SIZE: usize = std::mem::size_of::<ICMPHdr>();
// const ICMP_MAX_SIZE: usize = ETH_PAY_MAX_SIZE - IP_HDR_MINSIZE as usize;
const ICMP_PACKET_OFFSET: usize = ETH_HDR_SIZE + IP_HDR_MINSIZE as usize;

#[derive(TryFromPrimitive, PartialEq, Clone, Copy, Debug)]
#[repr(u8)]
pub enum ICMPProt {
    EchoReply = TYPE_ECHO_REPLY,
    EchoRequest = TYPE_ECHO_REQ,
    EchoUnreachable = TYPE_ECHO_UNREACHABLE,
}

impl Packet<ICMP> {
    pub fn parse(data: Packet<IP>) -> Result<Self, IpErr> {
        let packet = data.payload();

        if packet.len() < ICMP_HDR_SIZE {
            return Err(ICMPError("payload size smaller than ICMP hdr size".into()));
        }

        let check = calc_checksum_be(packet);
        if check != 0 {
            return Err(ICMPError(format!("invalid ICMP checksum: {check}")));
        }

        Ok(Packet::<ICMP>::from_vec(data.into_buf()))
    }

    /// service the incoming ICMP packet
    pub fn service(self, sip: Ipv4Addr, dip: Ipv4Addr) -> Option<Packet<IP>> {
        let icmp_slice = &self.as_buf()[IP_HDR_MINSIZE as usize + ETH_HDR_SIZE..];

        match ICMPProt::try_from(icmp_slice[0]).ok()? {
            ICMPProt::EchoRequest => {
                let reply = handle_echo_req(self);
                Packet::<IP>::new(dip, sip, reply.into()).ok()
            }
            ICMPProt::EchoReply => {
                debug!("got an echo reply!");
                None
            }
            _ => {
                debug!("unsupported ICMP package received");
                None
            }
        }
    }
}

#[derive(Default, Debug, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
struct ICMPHdr {
    msg_type: u8,
    code: u8,
    checksum: U16<BE>, // includes the payload!
}

const ECHO_HDR_SIZE: usize = size_of::<Echo>();
const UNREACHABLE_HDR_SIZE: usize = size_of::<Unreachable>();

#[derive(Default, Debug, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
struct Echo {
    id: U16<BE>,
    seq: U16<BE>,
}

impl std::fmt::Display for Echo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let id = self.id;
        let seq = self.seq;
        writeln!(
            f,
            "\nEcho:\n{:<10}{:>10}\n{:<10}{:>10}\n",
            "id", id, "seq", seq
        )
    }
}

#[derive(Default, Debug, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
struct Unreachable {
    unused: u8,
    len: u8,
    var: U16<BE>,
}

fn handle_echo_req(mut req: Packet<ICMP>) -> Packet<ICMP> {
    trace!("handling echo request");

    // ICMP portion of the packet
    let icmp_slice = &mut req.as_buf_mut()[ICMP_PACKET_OFFSET..];

    let echo_payload = Echo::ref_from_bytes(&icmp_slice[ICMP_HDR_SIZE..]).unwrap();
    trace!(seq = echo_payload.seq.get(), id = echo_payload.id.get());

    debug_assert!(icmp_slice.len() == 8);

    let rep_icmp_hdr = ICMPHdr {
        msg_type: TYPE_ECHO_REPLY,
        code: 0,
        checksum: 0.into(),
    };

    // copy empty hdr
    icmp_slice[..ICMP_HDR_SIZE].copy_from_slice(rep_icmp_hdr.as_bytes());

    // calculate checksum and write it back
    let checksum = calc_checksum_be(icmp_slice);
    icmp_slice[2..4].copy_from_slice(&checksum.to_be_bytes());

    debug_assert_eq!(0, calc_checksum_be(icmp_slice));

    req
}

// async fn handle_echo_req(req: Packet<IP>) -> Packet<IP> {
//     trace!("handling echo request");
//
//     let req_ip_hdr = req.hdr();
//     let req_ip_pay = req.payload();
//
//     let mut rep_icmp_hdr = ICMPHdr {
//         msg_type: TYPE_ECHO_REPLY,
//         code: 0,
//         checksum: 0.into(),
//     };
//
//     let mut icmp_buf = [0u8; ICMP_MAX_SIZE];
//     let pay_offset = req_ip_pay.len() - IP_HDR_MINSIZE as usize;
//
//     // copy ip payload
//     icmp_buf[..pay_offset].copy_from_slice(req_ip_pay);
//
//     // copy empty hdr
//     icmp_buf[..ICMP_HDR_SIZE].copy_from_slice(rep_icmp_hdr.as_bytes());
//
//     // calculate checksum
//     rep_icmp_hdr.checksum = calc_checksum_be(&icmp_buf[..pay_offset]).into();
//
//     // overwrite hdr with checksum
//     icmp_buf[..ICMP_HDR_SIZE].copy_from_slice(rep_icmp_hdr.as_bytes());
//
//     assert_eq!(0, calc_checksum_be(&icmp_buf[..pay_offset]));
//
//     let mut rep_ip_hdr = IPv4Hdr {
//         tos: TOS_BEST_EFFORT,
//         tot_len: req_ip_hdr.tot_len,
//         id: req_ip_hdr.id,
//         frag_off: 0,
//         ttl: TTL_START,
//         prot: IPPROTO_ICMP,
//         src_addr: tcup.addr().octets(),
//         dest_addr: req_ip_hdr.src_addr,
//         ..Default::default()
//     };
//
//     rep_ip_hdr.set_ihl(IP_HDR_MINSIZE)?;
//     rep_ip_hdr.checksum = calc_checksum_be(&rep_ip_hdr.into_be_bytes());
//
//     // look in ARP table
//     let dest_mac = tcup.arp_table_get(req_ip_hdr.src_addr.into()).unwrap();
//
//     // TODO: issue ARP request in case we dont have it
//
//     // build IP packet
//     let mut reply: Vec<u8> = Vec::with_capacity(ETH_HDR_SIZE + req_ip_hdr.tot_len as usize);
//     let rep_eth_hdr = EthHdr::new(dest_mac, tcup.mac(), ETH_P_IP);
//
//     reply.extend_from_slice(&rep_eth_hdr.into_be_bytes());
//     reply.extend_from_slice(&rep_ip_hdr.into_be_bytes());
//     reply.extend_from_slice(&icmp_buf[..pay_offset]);
//
//     assert_eq!(reply.len(), ETH_HDR_SIZE + req_ip_hdr.tot_len as usize);
//
//     let frame = EthPacket { data: reply };
//
//     debug!("reply eth:\n{}", rep_eth_hdr);
//     debug!("reply ip:\n{}", rep_ip_hdr);
//
//     let n = tcup.write_tap(frame).await?;
//     trace!("{n} bytes written");
//
//     todo!()
// }

// fn handle_echo_rep(icmp_payload: &[u8], host: &mut MockHost) -> Result<()> {
//     if icmp_payload.len() < ECHO_HDR_SIZE {
//         return Err("invalid ICMP payload size".into());
//     }

//     let echo_hdr = Echo::from_bytes(icmp_payload[..ECHO_HDR_SIZE].try_into()?);
//     let echo_payload = &icmp_payload[ECHO_HDR_SIZE..];

//     Ok(())
// }
