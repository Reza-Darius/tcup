use std::{collections::HashMap, net::Ipv4Addr};

use crate::error::Result;
use crate::tap::TAPDevice;
use crate::utils::mac_to_str;

#[derive(Debug)]
pub struct TCup {
    tap: TAPDevice,
    ip: Ipv4Addr,
    subnet: Option<u8>,
}

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
    pub table: HashMap<Ipv4Addr, MAC>,
    pub addr: Ipv4Addr,
    pub mac: MAC,
}

impl MockHost {
    pub fn new(ip: Ipv4Addr, mac: MAC) -> Self {
        MockHost {
            table: HashMap::new(),
            addr: ip,
            mac,
        }
    }
}
