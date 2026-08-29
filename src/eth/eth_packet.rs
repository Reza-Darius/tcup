use num_enum::TryFromPrimitive;
use zerocopy::{BE, FromBytes, Immutable, IntoBytes, KnownLayout, U16};

use super::mac::*;
use crate::eth::EthErr::{BuildError, InvalidProtError, ParseError};
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
            return Err(ParseError("data exceeds MTU size"));
        }

        // TODO: do we need more validaton?

        if data.len() < ETH_HDR_SIZE {
            return Err(ParseError("data below minimumt hdr size"));
        }

        let hdr = EthHdr::read_from_prefix(&data)
            .expect("eth parse: we checked the len")
            .0;

        let _: EthProt = hdr
            .prot_type
            .get()
            .try_into()
            .map_err(|_| InvalidProtError)?;

        Ok(Packet::from_vec(data))
    }

    pub fn into_parts(self) -> Result<(EthHdr, EthPayload), EthErr> {
        let hdr = *self.hdr();

        let pay = match self.prot() {
            EthProt::Arp => EthPayload::Arp(Packet::<Arp>::parse(self)?),
            EthProt::Ip => EthPayload::Ip(Packet::<Ipv4>::parse(self)?),
        };

        Ok((hdr, pay))
    }

    pub fn prot(&self) -> EthProt {
        u16::from_be_bytes(
            self.as_slice()[MAC_ADDR_LEN * 2..MAC_ADDR_LEN * 2 + 2]
                .try_into()
                .expect("get eth prot: packet is parsed and has the required length"),
        )
        .try_into()
        .expect("get eth prot: eth eth packet is parsed")
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
            }
            EthPayload::Ip(packet) => {
                prot = EthProt::Ip;
                packet.into_vec()
            }
        };

        let hdr = EthHdr::new(dmac, smac, prot);

        if data.len() < ETH_HDR_SIZE {
            return Err(BuildError("payload size doesnt add up"));
        }

        if data.len() > ETH_FRAME_MAX_SIZE {
            return Err(BuildError("payload is too large"));
        }

        // inserting padding
        if data.len() < ETH_FRAME_MIN_SIZE {
            data.resize(ETH_FRAME_MIN_SIZE, 0);
        }

        hdr.as_bytes()
            .write_to_prefix(&mut data)
            .expect("eth new: parsed frame has sufficient len");

        Ok(Packet::from_vec(data))
    }

    pub fn hdr(&self) -> &EthHdr {
        EthHdr::ref_from_prefix(self.as_slice())
            .expect("a parsed frame has sufficient len")
            .0
    }

    pub fn payload(&self) -> &[u8] {
        &self.as_slice()[ETH_PAY_OFFSET..]
    }
}

#[derive(Debug)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eth::arp::ArpMsg;
    use std::net::Ipv4Addr;

    const DMAC: [u8; MAC_ADDR_LEN] = [0xAA; MAC_ADDR_LEN];
    const SMAC: [u8; MAC_ADDR_LEN] = [0xBB; MAC_ADDR_LEN];

    fn valid_arp_eth_bytes() -> Vec<u8> {
        Packet::<Arp>::new_request(
            Mac::from_octets(SMAC),
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
        )
        .into_vec()
    }

    fn dummy_arp_msg() -> ArpMsg {
        ArpMsg {
            hwtype: libc::ARPHRD_ETHER.into(),
            prot_type: (libc::ETH_P_IP as u16).into(),
            hwsize: MAC_ADDR_LEN as u8,
            prosize: 4,
            opcode: libc::ARPOP_REQUEST.into(),
            smac: SMAC,
            sip: [10, 0, 0, 2],
            dmac: [0; MAC_ADDR_LEN],
            dip: [10, 0, 0, 1],
        }
    }

    #[test]
    fn sizes_match() {
        assert_eq!(ETH_HDR_SIZE + ETH_PAY_MIN_SIZE, ETH_FRAME_MIN_SIZE);
        assert_eq!(ETH_HDR_SIZE, MAC_ADDR_LEN * 2 + 2);
    }


    #[test]
    fn eth_prot() {
        assert!(EthProt::is_supported(libc::ETH_P_IP as u16));
        assert!(EthProt::is_supported(libc::ETH_P_ARP as u16));
        assert!(!EthProt::is_supported(libc::ETH_P_IPV6 as u16));
        assert!(!EthProt::is_supported(0xFFFF));
    }

    #[test]
    fn eth_hdr_new_stores_macs_and_prot_type() {
        let hdr = EthHdr::new(Mac::from_octets(DMAC), Mac::from_octets(SMAC), EthProt::Arp);
        assert_eq!(hdr.dmac, DMAC);
        assert_eq!(hdr.smac, SMAC);
        assert_eq!(hdr.prot_type.get(), libc::ETH_P_ARP as u16);
    }

    #[test]
    fn parse_rejects_data_over_mtu() {
        let data = vec![0u8; ETH_FRAME_MAX_SIZE + 1];
        let result = Packet::<Eth>::parse(data);
        assert!(matches!(result, Err(EthErr::ParseError(_))));
    }

    #[test]
    fn parse_rejects_data_below_header_size() {
        let data = vec![0u8; ETH_HDR_SIZE - 1];
        let result = Packet::<Eth>::parse(data);
        assert!(matches!(result, Err(EthErr::ParseError(_))));
    }

    #[test]
    fn parse_rejects_unsupported_ethertype() {
        let mut data = vec![0u8; ETH_FRAME_MIN_SIZE];
        data[0..MAC_ADDR_LEN].copy_from_slice(&DMAC);
        data[MAC_ADDR_LEN..MAC_ADDR_LEN * 2].copy_from_slice(&SMAC);

        // bogus ethertype
        data[MAC_ADDR_LEN * 2..MAC_ADDR_LEN * 2 + 2].copy_from_slice(&0xFFFFu16.to_be_bytes());

        let result = Packet::<Eth>::parse(data);
        assert!(matches!(result, Err(EthErr::InvalidProtError)));
    }

    #[test]
    fn parse_accepts_valid_arp_frame() {
        let data = valid_arp_eth_bytes();
        let packet = Packet::<Eth>::parse(data).expect("valid arp frame should parse");
        assert_eq!(packet.prot(), EthProt::Arp);
    }

    #[test]
    fn parse_roundtrips_header_fields() {
        let data = valid_arp_eth_bytes();
        let packet = Packet::<Eth>::parse(data).expect("should parse");
        let hdr = packet.hdr();
        assert_eq!(hdr.dmac, Mac::BROADCAST.octets());
        assert_eq!(hdr.smac, SMAC);
    }

    #[test]
    fn new_writes_requested_macs_and_prot_into_header() {
        let payload = EthPayload::Arp(Packet::<Arp>::new(dummy_arp_msg()));

        let eth = Packet::<Eth>::new(Mac::from_octets(DMAC), Mac::from_octets(SMAC), payload)
            .expect("valid construction");

        assert_eq!(eth.hdr().dmac, DMAC);
        assert_eq!(eth.hdr().smac, SMAC);
        assert_eq!(eth.prot(), EthProt::Arp);
    }

    #[test]
    fn new_rejects_oversized_payload() {
        // Bypass the normal Arp constructors (which always produce a
        // small, MTU-safe frame) to exercise the size guard directly.
        let oversized = EthPayload::Arp(Packet::<Arp>::from_vec(vec![0u8; ETH_FRAME_MAX_SIZE + 1]));

        let result = Packet::<Eth>::new(Mac::from_octets(DMAC), Mac::from_octets(SMAC), oversized);
        assert!(matches!(result, Err(EthErr::ParseError(_))));
    }

    // --- into_parts ---

    #[test]
    fn into_parts_routes_arp_frames_to_arp_variant() {
        let packet = Packet::<Eth>::parse(valid_arp_eth_bytes()).expect("should parse");
        let (hdr, payload) = packet.into_parts().expect("should split");
        assert_eq!(hdr.prot_type.get(), libc::ETH_P_ARP as u16);
        assert!(matches!(payload, EthPayload::Arp(_)));
    }
}
