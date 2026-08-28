use super::EthErr;
#[derive(Debug, Copy, Clone)]
pub struct Mac([u8; 6]);

pub const MAC_ADDR_LEN: usize = libc::ETH_ALEN as usize;

impl Mac {
    pub const BROADCAST: Self = Mac([0xFFu8; MAC_ADDR_LEN]);

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

impl std::fmt::Display for Mac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let buf = &self.0;
        write!(f,
            "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]
        )
    }
}

impl std::str::FromStr for Mac {
    type Err = EthErr;

    /// supports "00:00:00:00:00:00" notation
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut count = 0;
        let mut mac_parsed = [0u8; 6];

        for part in s.split(':') {
            if count == 6 {
                return Err(EthErr::Mac("invalid string for MAC conversion".into()));
            }
            mac_parsed[0] = part.parse::<u8>().map_err(|e| EthErr::Mac(format!("parse error: {e}")))?;
            count += 1;
        }
        if count != 6 {
                return Err(EthErr::Mac("invalid string for MAC conversion".into()));
        }

        Ok(Mac(mac_parsed))
    }
}

impl TryFrom<&str> for Mac {
    type Error = EthErr;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<&[u8; 6]> for Mac {
    fn from(value: &[u8; 6]) -> Self {
        Mac::from_octets(*value)
    }
}

impl From<[u8; 6]> for Mac {
    fn from(value: [u8; 6]) -> Self {
        Mac::from_octets(value)
    }
}
