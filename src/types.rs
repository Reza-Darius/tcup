use std::{collections::HashMap, net::Ipv4Addr};

use crate::error::Result;
use crate::eth::EthFrame;
use crate::utils::mac_to_str;
use tokio::sync::mpsc::Sender;

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Copy, Clone)]
pub struct MAC([u8; 6]);

impl std::fmt::Display for MAC {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", mac_to_str(&self.0))
    }
}

impl MAC {
    pub fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        MAC([a, b, c, d, e, f])
    }

    pub fn octets(&self) -> [u8; 6] {
        self.0
    }

    pub fn from_octets(octets: [u8; 6]) -> Self {
        MAC(octets)
    }

    /// supports "00:00:00:00:00:00" notation
    pub fn from_str(mac: &str) -> Result<Self> {
        let mut count = 0;
        let mut mac_parsed = [0u8; 6];

        for part in mac.split(':') {
            if count == 6 {
                return Err("invalid string for MAC conversiont".into());
            }
            mac_parsed[0] = part.parse::<u8>().map_err(|e| e.to_string())?;
            count += 1;
        }
        if count != 6 {
            return Err("invalid string for MAC conversiont".into());
        }

        Ok(MAC(mac_parsed))
    }
}

impl From<[u8; 6]> for MAC {
    fn from(value: [u8; 6]) -> Self {
        MAC::from_octets(value)
    }
}

#[derive(Debug)]
pub struct MockHost {
    pub arp_table: HashMap<Ipv4Addr, MAC>,
    pub addr: Ipv4Addr,
    pub mac: MAC,

    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct Socket {
    pub tx: Sender<EthFrame>,
}

impl MockHost {
    pub fn new(ip: Ipv4Addr, mac: MAC, port: u16) -> Self {
        MockHost {
            arp_table: HashMap::new(),
            addr: ip,
            mac,
            port,
        }
    }

    pub fn get_mac(&self, ip: impl Into<Ipv4Addr>) -> Option<MAC> {
        self.arp_table.get(&ip.into()).copied()
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct TCPCon {
    pub sip: Ipv4Addr,
    pub sport: u16,
    pub dip: Ipv4Addr,
    pub dport: u16,
}
