// #define ETH_ALEN	6		/* Octets in one ethernet addr	 */
// #define ETH_HLEN	14		/* Total octets in header.	 */
// #define ETH_ZLEN	60		/* Min. octets in frame sans FCS */
// #define ETH_DATA_LEN	1500		/* Max. octets in payload	 */
// #define ETH_FRAME_LEN	1514		/* Max. octets in frame sans FCS */
// #define ETH_FCS_LEN	4		/* Octets in the FCS		 */
// following sizes dont include FCS
const FCS_SIZE: usize = 4;
const ADDR_SIZE: usize = 6;
const ETH_FRAME_MIN_SIZE: usize = ETH_HDR_SIZE + PAYLOAD_MIN_SIZE;
const ETH_FRAME_MAX_SIZE: usize = PAYLOAD_MAX_SIZE + ETH_HDR_SIZE;
const ETH_HDR_SIZE: usize = 14;
const PAYLOAD_MIN_SIZE: usize = 46;
const PAYLOAD_MAX_SIZE: usize = 1500; // maximum payload size for a single frame

// ethernet header types (h_proto) big endian
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_P_ARP: u16 = 0x0806;

pub struct EthFrame {
    hdr: EthHeader,
    payload: Vec<u8>,
    fcs: [u8; FCS_SIZE],
}

#[repr(C, packed)]
pub struct EthHeader {
    dmac: [u8; ADDR_SIZE], // dest MAC address
    smac: [u8; ADDR_SIZE], // src MAC address
    h_proto: u16,
}

fn mac(buf: &[u8; 6]) -> String {
    format!(
        "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]
    )
}

impl std::fmt::Display for EthHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let dest_mac = mac(&self.dmac);
        let source_mac = mac(&self.smac);
        let hrd_type = match self.h_proto {
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
    pub fn parse(buf: &[u8; ETH_HDR_SIZE]) -> Self {
        let mut hdr = Self {
            dmac: [0; _],
            smac: [0; _],
            h_proto: 0,
        };

        hdr.dmac.copy_from_slice(&buf[..6]);
        hdr.smac.copy_from_slice(&buf[6..12]);
        hdr.h_proto = u16::from_be_bytes(buf[12..14].try_into().unwrap());

        hdr
    }
}
