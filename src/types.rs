use std::{collections::HashMap, net::Ipv4Addr};

use crate::utils::mac_to_str;

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Copy, Clone)]
pub struct Mac([u8; 6]);

impl std::fmt::Display for Mac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", mac_to_str(&self.0))
    }
}

impl Mac {
    pub fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        Mac([a, b, c, d, e, f])
    }

    pub fn octets(&self) -> [u8; 6] {
        self.0
    }

    pub fn from_octets(octets: [u8; 6]) -> Self {
        Mac(octets)
    }
}

impl std::str::FromStr for Mac {
    type Err = crate::error::Error;

    /// supports "00:00:00:00:00:00" notation
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut count = 0;
        let mut mac_parsed = [0u8; 6];

        for part in s.split(':') {
            if count == 6 {
                return Err("invalid string for MAC conversiont".into());
            }
            mac_parsed[0] = part.parse::<u8>().map_err(|e| e.to_string())?;
            count += 1;
        }
        if count != 6 {
            return Err("invalid string for MAC conversiont".into());
        }

        Ok(Mac(mac_parsed))
    }
}

impl From<[u8; 6]> for Mac {
    fn from(value: [u8; 6]) -> Self {
        Mac::from_octets(value)
    }
}

#[derive(Debug)]
pub struct MockHost {
    pub arp_table: HashMap<Ipv4Addr, Mac>,
    pub addr: Ipv4Addr,
    pub mac: Mac,

    pub port: u16,
}

impl MockHost {
    pub fn new(ip: Ipv4Addr, mac: Mac, port: u16) -> Self {
        MockHost {
            arp_table: HashMap::new(),
            addr: ip,
            mac,
            port,
        }
    }

    pub fn get_mac(&self, ip: impl Into<Ipv4Addr>) -> Option<Mac> {
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
