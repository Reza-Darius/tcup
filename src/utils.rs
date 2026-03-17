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
pub fn calc_checksum_be(bytes: &[u8]) -> u16 {
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

    !sum as u16
}

// pub fn calc_checksum_le(bytes: &[u8]) -> u16 {
//     let mut sum: u32 = 0;
//     let mut i = 0;

//     while i + 1 < bytes.len() {
//         let word = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
//         sum += word as u32;
//         i += 2;
//     }

//     if i < bytes.len() {
//         sum += (bytes[i] as u32) << 8;
//     }

//     while (sum >> 16) > 0 {
//         sum = (sum & 0xFFFF) + (sum >> 16);
//     }

//     sum = sum.swap_bytes();
//     !sum as u16
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum() -> Result<()> {
        // Example 1: normal order (BE)
        let ex1: [u8; 8] = [0x00, 0x01, 0xF2, 0x03, 0xF4, 0xF5, 0xF6, 0xF7];

        // Example 2: 16-bit swapped order
        let ex2: [u8; 8] = [0x01, 0x00, 0x03, 0xF2, 0xF5, 0xF4, 0xF7, 0xF6];

        // Example 3: 32-bit reversed order
        let ex3: [u8; 8] = [0x03, 0xF2, 0x01, 0x00, 0xF7, 0xF6, 0xF5, 0xF4];

        let expected: u16 = 0xDDF2;

        assert_eq!(expected, !calc_checksum_be(&ex1));
        // assert_eq!(expected, !calc_checksum_le(&ex2));
        // assert_eq!(expected, calc_checksum(&ex3).swap_bytes());
        Ok(())
    }
}
