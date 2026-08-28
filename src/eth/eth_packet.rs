use num_enum::TryFromPrimitive;
use zerocopy::{BE, FromBytes, Immutable, IntoBytes, KnownLayout, U16};

use super::mac::*;
use crate::eth::error::EthErr;
use crate::utils::packet::*;

/// bytes in FCS
pub const FCS_SIZE: usize = libc::ETH_FCS_LEN as usize;
/// min num of bytes in frame
pub const ETH_FRAME_MIN_SIZE: usize = libc::ETH_ZLEN as usize;
/// max size sans FCS
pub const ETH_FRAME_MAX_SIZE: usize = libc::ETH_FRAME_LEN as usize;
/// size of an ethernet header
pub const ETH_HDR_SIZE: usize = libc::ETH_HLEN as usize;
/// minimum size of ethernet payload
pub const ETH_PAY_MIN_SIZE: usize = ETH_FRAME_MIN_SIZE - ETH_HDR_SIZE;
/// maximum payload size for a single frame
pub const ETH_PAY_MAX_SIZE: usize = libc::ETH_DATA_LEN as usize;
/// offset at which the ethernet payload starts
const ETH_PAY_OFFSET: usize = ETH_HDR_SIZE;

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

impl EthProt {
    /// checks a little endian eth prot number
    pub fn is_supported(prot: u16) -> bool {
        <u16 as TryInto<EthProt>>::try_into(prot).is_ok()
    }
}

impl Packet<Eth> {
    pub fn parse(data: impl Into<Vec<u8>>) -> Result<Packet<Eth>, EthErr> {
        let data = data.into();

        if data.len() > ETH_FRAME_MAX_SIZE {
            return Err(EthErr::ParseError("data exceeds MTU size"));
        }

        // TODO: do we need more validaton?

        if data.len() < ETH_HDR_SIZE {
            return Err(EthErr::ParseError("data below minimumt hdr size"));
        }

        let hdr = EthHdr::read_from_prefix(&data)
            .expect("a parsed frame has sufficient len")
            .0;

        let _: EthProt = hdr
            .prot_type
            .get()
            .try_into()
            .map_err(|_| EthErr::InvalidProtError)?;

        Ok(Packet::from_vec(data))
    }

    pub fn into_parts(self) -> Result<(EthHdr, EthPayload), EthErr> {
        let hdr = self.hdr().clone();

        let pay = match self.prot() {
            EthProt::Arp => EthPayload::Arp(Packet::<Arp>::parse(self)?),
            EthProt::Ip => EthPayload::Ip(Packet::<Ipv4>::parse(self)?),
        };

        Ok((hdr, pay))
    }

    pub fn prot(&self) -> EthProt {
        u16::from_be_bytes(
            self.data[MAC_ADDR_LEN * 2..MAC_ADDR_LEN * 2 + 2]
                .try_into()
                .expect("packet is parsed and has the required length"),
        )
        .try_into()
        .expect("unable to read a support prot from eth frame")
    }

    /// construct a new frame, this reuses the payload allocation
    pub fn new(
        dmac: impl Into<Mac>,
        smac: impl Into<Mac>,
        payload: EthPayload,
    ) -> Result<Packet<Eth>, EthErr> {
        let prot;
        let mut data = match payload {
            EthPayload::Arp(packet) => {
                prot = EthProt::Arp;
                packet.into_vec()
            },
            EthPayload::Ip(packet) => {
                prot = EthProt::Ip;
                packet.into_vec()
            },
        };

        let hdr = EthHdr::new(dmac, smac, prot);

        if data.len() < ETH_HDR_SIZE {
            return Err(EthErr::ParseError("payload size doesnt add up"));
        }

        if data.len() > ETH_FRAME_MAX_SIZE {
            return Err(EthErr::ParseError("payload is too large"));
        }

        hdr.as_bytes()
            .write_to_prefix(&mut data)
            .expect("parsed frame has sufficient len");

        Ok(Packet::from_vec(data))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.data.as_ref()
    }

    pub fn hdr(&self) -> &EthHdr {
        EthHdr::ref_from_prefix(&self.data)
            .expect("a parsed frame has sufficient len")
            .0
        // Eth_hdr::from_be_bytes(
        //     self.0[..ETH_HDR_SIZE]
        //         .try_into()
        //         .expect("we never have a frame without a header"),
        // )
    }

    pub fn payload(&self) -> &[u8] {
        &self.data.as_slice()[ETH_PAY_OFFSET..]
    }

    // fn with_cap(cap: usize) -> Result<Self> {
    //     if cap == 0 {
    //         return Err("capacity cant be zero".into());
    //     }
    //     if cap > ETH_FRAME_MAX_SIZE {
    //         return Err("data exceeds MTU".into());
    //     }
    //     if cap < ETH_HDR_SIZE {
    //         return Err("data below minimum eth hdr size".into());
    //     }
    //
    //     Ok(EthFrame {
    //         data: vec![0u8; cap],
    //     })
    // }
    //
    //
    // pub fn get_eth_pay_mut(&mut self) -> Result<&mut [u8]> {
    //     if self.len() < ETH_PAY_OFFSET {
    //         return Err("no ETH payload found".into());
    //     }
    //
    //     Ok(&mut self.0.as_mut_slice()[ETH_PAY_OFFSET..])
    // }
    //
    // pub fn set_eth_pay(&mut self, data: &[u8]) -> Result<()> {
    //     if ETH_PAY_OFFSET + data.len() > ETH_FRAME_MAX_SIZE {
    //         return Err("data exceeds MTU".into());
    //     }
    //
    //     self.0.truncate(ETH_HDR_SIZE);
    //     self.0.extend_from_slice(data);
    //
    //     Ok(())
    // }
}

pub enum EthPayload {
    Arp(Packet<Arp>),
    Ip(Packet<Ipv4>),
}

impl From<Packet<Arp>> for EthPayload {
    fn from(value: Packet<Arp>) -> Self {
        EthPayload::Arp(value)
    }
}

impl From<Packet<Ipv4>> for EthPayload {
    fn from(value: Packet<Ipv4>) -> Self {
        EthPayload::Ip(value)
    }
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct EthHdr {
    pub dmac: [u8; MAC_ADDR_LEN], // dest MAC address
    pub smac: [u8; MAC_ADDR_LEN], // src MAC address
    pub prot_type: U16<BE>,
}

impl std::fmt::Display for EthHdr {
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
            "dmac: {}, smac: {}, type: {}",
            dest_mac, source_mac, hrd_type
        )
    }
}

impl EthHdr {
    pub fn new(dmac: impl Into<Mac>, smac: impl Into<Mac>, prot_type: EthProt) -> Self {
        EthHdr {
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
