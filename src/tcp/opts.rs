use crate::tcp::{
    error::TCPError::{self, OptionError},
    tcp_packet::TCP_OPT_MAX_SIZE,
};

// TCP option kinds
const OPT_EOL: u8 = 0;
const OPT_NOP: u8 = 1;
const OPT_MSS: u8 = 2;
const OPT_MSS_LEN: usize = 4;
const OPT_WSCL: u8 = 3;
const OPT_WSCL_LEN: usize = 3;
const OPT_SACK_PERM: u8 = 4;
const OPT_SACK_PERM_LEN: usize = 2;
const OPT_SACK: u8 = 5; // n size
const OPT_TIME_STMP: u8 = 8;
const OPT_TIME_STMP_LEN: usize = 10;
const OPT_FAST_OPEN: u8 = 34; // n size

#[derive(Debug, Default, Clone, Copy)]
pub struct TCPOpts {
    pub mss: Option<u16>, // max segment size, usually 1460
    pub wnd_scl: Option<u8>,
    pub sack_perm: bool,
    pub time_stamp: Option<(u32, u32)>,
}

impl TCPOpts {
    fn raw_len(&self) -> usize {
        let mut len = 0;
        if self.mss.is_some() {
            len += OPT_MSS_LEN;
        }
        if self.wnd_scl.is_some() {
            len += OPT_WSCL_LEN;
        }
        if self.sack_perm {
            len += OPT_SACK_PERM_LEN;
        }
        if self.time_stamp.is_some() {
            len += OPT_TIME_STMP_LEN;
        }
        len
    }

    /// size on the wire, padded up to 32-bits
    pub fn len(&self) -> usize {
        (self.raw_len() + 3) & !3
    }

    pub fn is_empty(&self) -> bool {
        self.raw_len() == 0
    }

    // There are two cases for the format of an option:
    //
    //       Case 1:  A single octet of option-kind.
    //
    //       Case 2:  An octet of option-kind, an octet of option-length, and
    //                the actual option-data octets.
    //
    //     The option-length counts the two octets of option-kind and
    //     option-length as well as the option-data octets.
    pub fn from_be_bytes(mut bytes: &[u8]) -> Result<Self, TCPError> {
        let mut opts = TCPOpts::default();

        while let Some((&kind, rest)) = bytes.split_first() {
            match kind {
                OPT_EOL => break,
                OPT_NOP => {
                    bytes = rest;
                    continue;
                }
                _ => {}
            }

            let Some(&len) = rest.first() else {
                return Err(OptionError("option kind without length".into()));
            };
            let len = len as usize;
            if len < 2 || len > bytes.len() {
                return Err(OptionError("invalid TCP option length".into()));
            }
            let body = &bytes[2..len];

            match kind {
                OPT_MSS => {
                    let b: [u8; 2] = body
                        .try_into()
                        .map_err(|_| OptionError("invalid MSS length".into()))?;
                    opts.mss = Some(u16::from_be_bytes(b));
                }
                OPT_WSCL => {
                    let [shift] = body else {
                        return Err(OptionError("invalid window scale length".into()));
                    };
                    opts.wnd_scl = Some(*shift);
                }
                OPT_SACK_PERM => {
                    if !body.is_empty() {
                        return Err(OptionError("invalid SACK permitted length".into()));
                    }
                    opts.sack_perm = true;
                }
                OPT_TIME_STMP => {
                    if body.len() != 8 {
                        return Err(OptionError("invalid timestamp length".into()));
                    }
                    let val = u32::from_be_bytes(body[..4].try_into().unwrap());
                    let ecr = u32::from_be_bytes(body[4..].try_into().unwrap());
                    opts.time_stamp = Some((val, ecr));
                }
                _ => {} // unsupported
            }

            bytes = &bytes[len..];
        }
        Ok(opts)
    }

    pub fn into_be_bytes(self) -> TCPOptsBytes {
        let mut buf = [0u8; TCP_OPT_MAX_SIZE];
        let mut i = 0;
        let mut put = |bytes: &[u8]| {
            buf[i..i + bytes.len()].copy_from_slice(bytes);
            i += bytes.len();
        };

        if let Some(mss) = self.mss {
            put(&[OPT_MSS, OPT_MSS_LEN as u8]);
            put(&mss.to_be_bytes());
        }
        if self.sack_perm {
            put(&[OPT_SACK_PERM, OPT_SACK_PERM_LEN as u8]);
        }
        if let Some((val, ecr)) = self.time_stamp {
            put(&[OPT_TIME_STMP, OPT_TIME_STMP_LEN as u8]);
            put(&val.to_be_bytes());
            put(&ecr.to_be_bytes());
        }
        if let Some(shift) = self.wnd_scl {
            put(&[OPT_WSCL, OPT_WSCL_LEN as u8, shift]);
        }

        TCPOptsBytes {
            data: buf,
            len: self.len(),
        }
    }
}

/// wrapper for a byte array
pub struct TCPOptsBytes {
    data: [u8; TCP_OPT_MAX_SIZE],
    len: usize,
}

impl std::ops::Deref for TCPOptsBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data[..self.len]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full() -> TCPOpts {
        TCPOpts {
            mss: Some(1460),
            wnd_scl: Some(7),
            sack_perm: true,
            time_stamp: Some((0xdead_beef, 0x1234_5678)),
        }
    }

    #[test]
    fn len_is_padded_to_word() {
        assert_eq!(TCPOpts::default().len(), 0);
        assert!(TCPOpts::default().is_empty());
        let mss = TCPOpts {
            mss: Some(1460),
            ..Default::default()
        };
        assert_eq!(mss.len(), 4);
        let mss_ws = TCPOpts {
            mss: Some(1460),
            wnd_scl: Some(7),
            ..Default::default()
        };
        assert_eq!(mss_ws.len(), 8); // 7 -> 8
        assert_eq!(full().len(), 20); // 19 -> 20
        for o in [mss, mss_ws, full()] {
            assert_eq!(o.len() % 4, 0);
            assert!(o.len() <= TCP_OPT_MAX_SIZE);
        }
    }

    #[test]
    fn serialized_len_matches_len() {
        for o in [
            TCPOpts::default(),
            full(),
            TCPOpts {
                sack_perm: true,
                ..Default::default()
            },
        ] {
            assert_eq!(o.into_be_bytes().len(), o.len());
        }
    }

    #[test]
    fn mss_wire_format() {
        let o = TCPOpts {
            mss: Some(1460),
            ..Default::default()
        };
        assert_eq!(&*o.into_be_bytes(), &[2, 4, 0x05, 0xb4]);
    }

    #[test]
    fn roundtrip_all() {
        let o = full();
        let parsed = TCPOpts::from_be_bytes(&o.into_be_bytes()).unwrap();
        assert_eq!(parsed.mss, o.mss);
        assert_eq!(parsed.wnd_scl, o.wnd_scl);
        assert_eq!(parsed.sack_perm, o.sack_perm);
        assert_eq!(parsed.time_stamp, o.time_stamp);
    }

    #[test]
    fn parses_without_eol() {
        let o = TCPOpts::from_be_bytes(&[2, 4, 0x05, 0xb4]).unwrap();
        assert_eq!(o.mss, Some(1460));
    }

    #[test]
    fn parses_linux_style_syn() {
        // MSS, SACK_PERM, TS, NOP, WSCL
        let raw = [
            2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7,
        ];
        let o = TCPOpts::from_be_bytes(&raw).unwrap();
        assert_eq!(o.mss, Some(1460));
        assert!(o.sack_perm);
        assert_eq!(o.time_stamp, Some((1, 0)));
        assert_eq!(o.wnd_scl, Some(7));
    }

    #[test]
    fn eol_stops_parsing() {
        let o = TCPOpts::from_be_bytes(&[0, 2, 4, 0x05, 0xb4]).unwrap();
        assert_eq!(o.mss, None);
    }

    #[test]
    fn nops_are_skipped() {
        let o = TCPOpts::from_be_bytes(&[1, 1, 3, 3, 9, 1]).unwrap();
        assert_eq!(o.wnd_scl, Some(9));
    }

    #[test]
    fn unknown_option_is_skipped() {
        // kind 5 (SACK block) len 10, followed by MSS
        let raw = [5, 10, 0, 0, 0, 1, 0, 0, 0, 2, 2, 4, 0x02, 0x00];
        assert_eq!(TCPOpts::from_be_bytes(&raw).unwrap().mss, Some(512));
    }

    #[test]
    fn malformed_is_rejected() {
        assert!(TCPOpts::from_be_bytes(&[2]).is_err()); // no len byte
        assert!(TCPOpts::from_be_bytes(&[2, 1]).is_err()); // len < 2
        assert!(TCPOpts::from_be_bytes(&[2, 4, 0x05]).is_err()); // truncated
        assert!(TCPOpts::from_be_bytes(&[2, 3, 0x05]).is_err()); // wrong MSS len
        assert!(TCPOpts::from_be_bytes(&[3, 4, 1, 2]).is_err()); // wrong WSCL len
        assert!(TCPOpts::from_be_bytes(&[8, 4, 1, 2]).is_err()); // wrong TS len
    }

    #[test]
    fn empty_ok() {
        assert!(TCPOpts::from_be_bytes(&[]).unwrap().is_empty());
    }
}
