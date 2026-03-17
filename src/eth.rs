use bytemuck::{Pod, Zeroable};
use tracing::instrument;

use crate::arp::handle_arp;
use crate::error::Result;
use crate::ip::{IP_HDR_MINSIZE, IP_hdr, handle_ip_frame};
use crate::tap::TAPDevice;
use crate::tcp::TCP_HDR_MINSIZE;
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
const IP_PAY_OFFSET: usize = ETH_HDR_SIZE + IP_HDR_MINSIZE;

const TCP_HDR_OFFSET: usize = ETH_HDR_SIZE + IP_HDR_MINSIZE;
const TCP_PAY_OFFSET: usize = ETH_HDR_SIZE + IP_HDR_MINSIZE + TCP_HDR_MINSIZE;

#[derive(Debug, Default, Clone)]
pub struct EthFrame {
    // network order bytes
    pub data: Vec<u8>,
    // additional offsets in case of option fields, TODO: pack both lengths into a single u8
    pub ip_hdr_offset: u8,
    pub tcp_hdr_offset: u8,
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
            ..Default::default()
        })
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.data.as_slice()
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
        if self.data.len() < IP_HDR_OFFSET + IP_HDR_MINSIZE {
            return Err("data too small to write IP hdr".into());
        }

        self.data.as_mut_slice()[IP_HDR_OFFSET..IP_HDR_OFFSET + IP_HDR_MINSIZE]
            .copy_from_slice(&hdr.into_be_bytes());

        Ok(())
    }

    pub fn get_ip_pay(&self) -> Result<&[u8]> {
        if self.len() < IP_PAY_OFFSET + self.ip_hdr_offset as usize {
            return Err("no IP payload found".into());
        }

        Ok(&self.data.as_slice()[IP_PAY_OFFSET + self.ip_hdr_offset as usize..])
    }

    pub fn get_ip_pay_mut(&mut self) -> Result<&mut [u8]> {
        if self.len() < IP_PAY_OFFSET + self.ip_hdr_offset as usize {
            return Err("no IP payload found".into());
        }

        Ok(&mut self.data.as_mut_slice()[IP_PAY_OFFSET + self.ip_hdr_offset as usize..])
    }

    pub fn set_ip_pay(&mut self, data: &[u8]) -> Result<()> {
        if IP_PAY_OFFSET + data.len() > ETH_FRAME_MAX_SIZE {
            return Err("data exceeds MTU".into());
        }

        self.data
            .truncate(IP_PAY_OFFSET + self.ip_hdr_offset as usize);
        self.data.extend_from_slice(data);

        Ok(())
    }
}

#[derive(Debug, Default, Pod, Zeroable, Clone, Copy)]
#[repr(C, packed)]
pub struct Eth_hdr {
    dmac: [u8; MAC_ADDR_LEN], // dest MAC address
    smac: [u8; MAC_ADDR_LEN], // src MAC address
    prot_type: u16,
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
pub fn handle_frame(frame: EthFrame, tap: &TAPDevice, host: &mut MockHost) -> Result<()> {
    let hdr = frame.get_eth_hdr();
    println!("{}", hdr);

    // TODO: discard frame if its not directed at us

    match hdr.prot_type {
        ETH_P_IP => {
            handle_ip_frame(frame, tap, host)?;
        }
        ETH_P_ARP => {
            handle_arp(frame, tap, host)?;
        }
        ETH_P_IPV6 => (),
        _ => return Err("unsupported frame type".into()),
    };

    Ok(())
}
