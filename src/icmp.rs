/*
 * Internet Control Message Protocol (ICMP)
 */

use std::sync::Arc;

use bytemuck::{Pod, Zeroable};
use tracing::info;

use crate::error::Result;
use crate::eth::{ETH_HDR_SIZE, ETH_P_IP, ETH_PAY_MAX_SIZE, Eth_hdr, EthFrame};
use crate::ip::{IP_HDR_MINSIZE, IP_hdr, IPPROTO_ICMP, TOS_BEST_EFFORT, TTL_START};
use crate::types::TCup;
use crate::{tap::TAPDevice, types::MockHost, utils::calc_checksum_be};

const TYPE_ECHO_REPLY: u8 = 0;
const TYPE_ECHO_REQ: u8 = 8;
const TYPE_ECHO_UNREACHABLE: u8 = 3;

const CODE_NET_UNREACHABLE: u8 = 0;
const ICMP_HDR_SIZE: usize = 4;
const ICMP_MAX_SIZE: usize = ETH_PAY_MAX_SIZE - IP_HDR_MINSIZE;

#[derive(Debug, Copy, Clone, Default, Pod, Zeroable)]
#[repr(C, packed)]
pub struct ICMP_hdr {
    msg_type: u8,
    code: u8,
    checksum: u16, // includes the payload!
}

impl ICMP_hdr {
    pub fn from_be_bytes(bytes: &[u8; ICMP_HDR_SIZE]) -> Self {
        let mut hdr: Self = bytemuck::cast(*bytes);
        hdr.checksum = u16::from_be(hdr.checksum);
        hdr
    }

    pub fn into_be_bytes(mut self) -> [u8; ICMP_HDR_SIZE] {
        self.checksum = u16::to_be(self.checksum);
        bytemuck::cast(self)
    }
}

const ECHO_HDR_SIZE: usize = size_of::<Echo>();
const UNREACHABLE_HDR_SIZE: usize = size_of::<Unreachable>();

#[derive(Debug, Copy, Clone, Default, Pod, Zeroable)]
#[repr(C, packed)]
struct Echo {
    id: u16,
    seq: u16,
}

impl Echo {
    fn from_be_bytes(data: &[u8; ECHO_HDR_SIZE]) -> Self {
        let mut e: Echo = bytemuck::cast(*data);
        e.id = u16::from_be(e.id);
        e.seq = u16::from_be(e.seq);
        e
    }

    fn into_be_bytes(mut self) -> [u8; ECHO_HDR_SIZE] {
        self.id = u16::to_be(self.id);
        self.seq = u16::to_be(self.seq);
        bytemuck::cast(self)
    }
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

#[derive(Debug, Copy, Clone, Default, Pod, Zeroable)]
#[repr(C, packed)]
struct Unreachable {
    unused: u8,
    len: u8,
    var: u16,
}

impl Unreachable {
    fn from_be_bytes(data: &[u8; UNREACHABLE_HDR_SIZE]) -> Self {
        let mut u: Unreachable = bytemuck::cast(*data);
        u.var = u16::from_be(u.var);
        u
    }
}

pub async fn handle_icmp(inc: EthFrame, tcup: Arc<TCup>, host: &mut MockHost) -> Result<()> {
    let ip_payload = inc.get_ip_pay()?;

    if ip_payload.len() < ICMP_HDR_SIZE {
        return Err("payload size smaller than ICMP hdr size".into());
    }

    let check = calc_checksum_be(ip_payload);
    if check != 0 {
        return Err(format!("invalid ICMP checksum: {check}").into());
    }

    match ip_payload[0] {
        TYPE_ECHO_REQ => handle_echo_req(inc, tcup, host).await,
        // TYPE_ECHO_REPLY => handle_echo_rep(packet, host)?,
        _ => unimplemented!(),
    }
}

async fn handle_echo_req(req: EthFrame, tcup: Arc<TCup>, host: &mut MockHost) -> Result<()> {
    info!("handling echo request");

    let req_ip_hdr = req.get_ip_hdr()?;
    let req_ip_pay = req.get_ip_pay()?;

    let req_ip_len = req_ip_hdr.tot_len as usize;

    let mut rep_icmp_hdr = ICMP_hdr {
        msg_type: TYPE_ECHO_REPLY,
        code: 0,
        checksum: 0,
    };

    let mut icmp_buf = [0u8; ICMP_MAX_SIZE];
    let pay_offset = req_ip_len - IP_HDR_MINSIZE;

    // copy ip payload
    icmp_buf[..pay_offset].copy_from_slice(req_ip_pay);

    // copy empty hdr
    icmp_buf[..ICMP_HDR_SIZE].copy_from_slice(&rep_icmp_hdr.into_be_bytes());

    // calculate checksum
    rep_icmp_hdr.checksum = calc_checksum_be(&icmp_buf[..pay_offset]);

    // overwrite hdr with checksum
    icmp_buf[..ICMP_HDR_SIZE].copy_from_slice(&rep_icmp_hdr.into_be_bytes());

    assert_eq!(0, calc_checksum_be(&icmp_buf[..pay_offset]));

    let mut rep_ip_hdr = IP_hdr {
        tos: TOS_BEST_EFFORT,
        tot_len: req_ip_hdr.tot_len,
        id: req_ip_hdr.id,
        frag_off: 0,
        ttl: TTL_START,
        prot: IPPROTO_ICMP,
        src_addr: host.addr.octets(),
        dest_addr: req_ip_hdr.src_addr,
        ..Default::default()
    };

    rep_ip_hdr.set_ihl(IP_HDR_MINSIZE)?;
    rep_ip_hdr.checksum = calc_checksum_be(&rep_ip_hdr.into_be_bytes());

    // look in ARP table
    let dest_mac = host.get_mac(req_ip_hdr.src_addr).unwrap();

    // TODO: issue ARP request in case we dont have it

    // build IP packet
    let mut reply: Vec<u8> = Vec::with_capacity(ETH_HDR_SIZE + req_ip_hdr.tot_len as usize);
    let rep_eth_hdr = Eth_hdr::new(dest_mac, host.mac, ETH_P_IP);

    reply.extend_from_slice(&rep_eth_hdr.into_be_bytes());
    reply.extend_from_slice(&rep_ip_hdr.into_be_bytes());
    reply.extend_from_slice(&icmp_buf[..pay_offset]);

    assert_eq!(reply.len(), ETH_HDR_SIZE + req_ip_hdr.tot_len as usize);

    let frame = EthFrame {
        data: reply,
        ..Default::default()
    };

    println!("reply eth: {}\n", rep_eth_hdr);
    println!("reply ip: {}", rep_ip_hdr);

    let n = tcup.write_tap(frame).await?;
    println!("{n} bytes written");

    Ok(())
}

// fn handle_echo_rep(icmp_payload: &[u8], host: &mut MockHost) -> Result<()> {
//     if icmp_payload.len() < ECHO_HDR_SIZE {
//         return Err("invalid ICMP payload size".into());
//     }

//     let echo_hdr = Echo::from_bytes(icmp_payload[..ECHO_HDR_SIZE].try_into()?);
//     let echo_payload = &icmp_payload[ECHO_HDR_SIZE..];

//     Ok(())
// }
