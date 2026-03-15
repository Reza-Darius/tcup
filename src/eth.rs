use bytemuck::{Pod, Zeroable};
use tracing::instrument;

use crate::arp::handle_arp;
use crate::error::Result;
use crate::ip::handle_ip_frame;
use crate::tap::TAPDevice;
use crate::types::{MAC, MockHost};
use crate::utils::mac_to_str;

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
pub const ETH_FRAME_MIN_SIZE: usize = ETH_HDR_SIZE + PAYLOAD_MIN_SIZE; // min size sans FCS
pub const ETH_FRAME_MAX_SIZE: usize = PAYLOAD_MAX_SIZE + ETH_HDR_SIZE; // max size sans FCS
pub const ETH_HDR_SIZE: usize = 14;
const PAYLOAD_MIN_SIZE: usize = 46;
const PAYLOAD_MAX_SIZE: usize = 1500; // maximum payload size for a single frame (MTU)

// ethernet header types (prot_type) big endian
// EtherType fields (IEEE 802 numbers)
pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86DD;
pub const ETH_P_ARP: u16 = 0x0806;

#[derive(Debug, Default)]
pub struct EthFrame {
    pub hdr: EthHeader,
    pub payload: Box<[u8]>,
    // fcs: [u8; FCS_SIZE], // not needed for our implementation
}

impl EthFrame {
    pub fn new(dmac: MAC, smac: MAC, eth_type: u16, payload: &[u8]) -> Self {
        EthFrame {
            hdr: EthHeader {
                dmac: dmac.octets(),
                smac: smac.octets(),
                prot_type: eth_type,
            },
            payload: Box::from(payload),
        }
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < ETH_HDR_SIZE {
            return Err(format!("Error: frame is too small, len: {}", data.len()).into());
        };

        Ok(EthFrame {
            hdr: EthHeader::from_bytes(&data[..14].try_into().expect("we checked the length")),
            payload: Box::from(&data[14..]),
        })
    }

    pub fn into_bytes(self) -> Vec<u8> {
        let size = ETH_HDR_SIZE + self.payload.len();
        let mut data = Vec::with_capacity(size);

        data.extend_from_slice(&self.hdr.into_bytes());
        data.extend_from_slice(&self.payload);

        data
    }
}

impl std::fmt::Display for EthFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Header:\n{}\nPayload:\n{:?}", self.hdr, self.payload)
    }
}

#[derive(Debug, Default, Pod, Zeroable, Clone, Copy)]
#[repr(C, packed)]
pub struct EthHeader {
    dmac: [u8; MAC_ADDR_LEN], // dest MAC address
    smac: [u8; MAC_ADDR_LEN], // src MAC address
    prot_type: u16,
}

impl std::fmt::Display for EthHeader {
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
            "dest MAC:{}\nsource MAC:{}\ntype:{}",
            dest_mac, source_mac, hrd_type
        )
    }
}

impl EthHeader {
    pub fn from_bytes(buf: &[u8; ETH_HDR_SIZE]) -> Self {
        let mut hdr: EthHeader = bytemuck::cast(*buf);
        hdr.prot_type = u16::from_be(hdr.prot_type);
        hdr
    }

    pub fn into_bytes(mut self) -> [u8; ETH_HDR_SIZE] {
        self.prot_type = u16::to_be(self.prot_type);
        bytemuck::cast(self)
    }
}

#[instrument(skip_all)]
pub fn handle_frame(frame: EthFrame, tap: &TAPDevice, host: &mut MockHost) -> Result<()> {
    println!("{}", frame.hdr);

    match frame.hdr.prot_type {
        ETH_P_IP => {
            // TODO
            handle_ip_frame(&frame.payload)?;
        }
        ETH_P_ARP => {
            if let Some(arp_packet) = handle_arp(&frame.payload, host) {
                let frame = EthFrame::new(
                    arp_packet.dmac.into(),
                    host.mac,
                    ETH_P_ARP,
                    &arp_packet.into_bytes(),
                );

                println!("reply frame:\n{frame}\n");

                let n = tap.write(frame)?;
                println!("{n} bytes written");
            }
        }
        ETH_P_IPV6 => (),
        _ => return Err("unsupported frame type".into()),
    };

    Ok(())
}
