use std::str::FromStr;
use std::{collections::HashMap, net::Ipv4Addr};

use crate::error::Result;
use crate::eth::EthFrame;
use crate::tap::TAPDevice;
use crate::utils::{mac_to_str, setup_cap};
use parking_lot::RwLock;
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
}

#[derive(Debug, Clone)]
pub struct Socket {
    pub tx: Sender<EthFrame>,
}

impl MockHost {
    pub fn new(ip: Ipv4Addr, mac: MAC) -> Self {
        MockHost {
            arp_table: HashMap::new(),
            addr: ip,
            mac,
        }
    }

    pub fn get_mac(&self, ip: impl Into<Ipv4Addr>) -> Option<MAC> {
        self.arp_table.get(&ip.into()).copied()
    }
}

#[derive(Debug)]
pub struct TCup {
    pub ip: Ipv4Addr,
    pub tap: TAPDevice,
    pub con_table: RwLock<HashMap<ConnectionKey, Socket>>,
}

impl TCup {
    pub fn init(name: &str, addr: &str) -> Result<Self> {
        setup_cap()?;

        let tap = TAPDevice::new(name)?;
        tap.set_if_link()?;
        tap.set_if_addr(addr)?;

        let tcup = TCup {
            ip: Ipv4Addr::from_str(addr)?,
            tap,
            con_table: RwLock::new(HashMap::new()),
        };

        Ok(tcup)
    }

    /// reads from the TAP device
    pub async fn read_tap(&self, buf: &mut [u8]) -> Result<usize> {
        self.tap.read(buf).await
    }

    /// writes to the TAP device
    pub async fn write_tap(&self, frame: EthFrame) -> Result<usize> {
        self.tap.write(frame).await
    }

    // pub fn get_socket(&self, con_k: &ConnectionKey) -> Option<&Socket> {
    //     self.con_table.read().table.get(con_k)
    // }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConnectionKey {
    pub source_ip: Ipv4Addr,
    pub source_port: u16,
    pub destination_ip: Ipv4Addr,
    pub destination_port: u16,
}
