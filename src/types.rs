use std::{net::Ipv4Addr, u32};

use crate::utils::mac_to_str;

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

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct TCPCon {
    pub local_ip: Ipv4Addr,
    pub local_port: u16,
    pub remote_ip: Ipv4Addr,
    pub remote_port: u16,
}
