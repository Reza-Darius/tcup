use crate::error::Result;
use caps::{CapSet, Capability};
use std::io;

pub fn setup_cap() -> Result<()> {
    // Add CAP_NET_ADMIN to inheritable set
    caps::raise(None, CapSet::Inheritable, Capability::CAP_NET_ADMIN)?;

    let r = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_RAISE,
            Capability::CAP_NET_ADMIN as i32,
            0,
            0,
        )
    };

    if r != 0 {
        return Err(io::Error::last_os_error().into());
    }

    Ok(())
}

pub fn mac_to_str(buf: &[u8; 6]) -> String {
    format!(
        "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]
    )
}

/// assumes network order bytes
pub fn calc_checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    while i + 1 < bytes.len() {
        let word = u16::from_be_bytes([bytes[i], bytes[i + 1]]);
        sum += word as u32;
        i += 2;
    }

    if i < bytes.len() {
        sum += (bytes[i] as u32) << 8;
    }

    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}
