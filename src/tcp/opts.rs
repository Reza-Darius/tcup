use crate::{error::Result, tcp::TCP_OPT_MAX_SIZE};

#[derive(Debug, Default, Clone, Copy)]
pub struct TCP_opts {
    pub mss: Option<u16>, // max segment size, usually 1460
    pub wnd_scl: Option<u8>,
    pub sack_perm: bool,
    pub time_stamp: Option<(u32, u32)>,
}

impl TCP_opts {
    /// calculates the size of the header
    pub fn len(&self) -> usize {
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
}

/// wrapper for a byte array
pub struct TCP_opts_bytes {
    data: [u8; TCP_OPT_MAX_SIZE],
    len: usize,
}

impl std::ops::Deref for TCP_opts_bytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe { std::slice::from_raw_parts(self.data.as_ptr(), self.len) }
    }
}

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

impl TCP_opts {
    pub fn from_be_bytes(mut tcp_opts: &[u8]) -> Result<Self> {
        let mut opts = TCP_opts::default();

        while !tcp_opts.is_empty() {
            match tcp_opts {
                [OPT_EOL, ..] => return Ok(opts),
                [OPT_NOP, rest @ ..] => tcp_opts = rest,
                [kind, len, rest @ ..] => {
                    let len = *len as usize;
                    if len < 2 || rest.len() < len - 2 {
                        return Err("invalid TCP option length".into());
                    }

                    match *kind {
                        OPT_MSS => {
                            if len != OPT_MSS_LEN {
                                return Err("invalid MSS length".into());
                            }
                            opts.mss = Some(u16::from_be_bytes([rest[0], rest[1]]))
                        }
                        // OPT_WSCL => {
                        //     if len != OPT_WSCL_LEN {
                        //         return Err("invalid window scale length".into());
                        //     }
                        //     opts.wnd_scl = Some(rest[0]);
                        // }
                        // OPT_SACK_PERM => {
                        //     opts.sack_perm = true;
                        // }
                        // OPT_TIME_STMP => {
                        //     if len != OPT_TIME_STMP_LEN {
                        //         return Err("invalid window scale length".into());
                        //     }

                        //     let ts_val = u32::from_be_bytes(rest[..4].try_into()?);
                        //     let ts_ecr = u32::from_be_bytes(rest[4..8].try_into()?);

                        //     opts.time_stamp = Some((ts_val, ts_ecr));
                        // }
                        _ => return Err("unsupported TCP options".into()),
                    }

                    tcp_opts = &tcp_opts[len..];
                }
                _ => return Err("unsupported TCP option".into()),
            }
        }
        Err("option slice ended before EOL".into())
    }

    /// returns the data slice and the len of actual data
    pub fn into_be_bytes(self) -> TCP_opts_bytes {
        let mut buf = [0u8; TCP_OPT_MAX_SIZE];
        let mut i = 0;

        fn set_len(len: usize, buf: &mut [u8], i: &mut usize) {
            let len = len as u8;
            buf[*i..*i + 1].copy_from_slice(&len.to_be_bytes());
            *i += 1;
        }

        if let Some(mss) = self.mss {
            buf[i] = OPT_MSS;
            i += 1;

            set_len(OPT_MSS_LEN, &mut buf, &mut i);

            buf[i..i + size_of::<u16>()].copy_from_slice(&mss.to_be_bytes());
            i += size_of::<u16>();
        }

        if let Some(mss) = self.wnd_scl {
            buf[i] = OPT_WSCL;
            i += 1;

            set_len(OPT_WSCL_LEN, &mut buf, &mut i);

            buf[i..i + size_of::<u8>()].copy_from_slice(&mss.to_be_bytes());
            i += size_of::<u8>();

            // one byte padding
            buf[i] = OPT_NOP;
        }

        // TODO: rest of options

        TCP_opts_bytes { data: buf, len: i }
    }
}
