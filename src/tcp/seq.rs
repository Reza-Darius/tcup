use std::{
    cmp::Ordering,
    hash::{Hash, Hasher},
};

use derive_more::{Add, Display, Div, Mul};
use siphasher::sip::SipHasher13;

use crate::{tcp::timer::TICK, types::TCPCon};

#[derive(Debug, Clone, Copy, Display, Add, Mul, Div)]
struct Seq(u32);

impl Seq {
    pub fn new(con: &TCPCon) -> Self {
        let key: &[u8; 16] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let mut hasher = SipHasher13::new_with_key(key);

        TICK.load(std::sync::atomic::Ordering::Relaxed)
            .hash(&mut hasher);
        con.hash(&mut hasher);

        Seq(hasher.finish() as u32)
    }

    // pub fn cmp(&self, other: Seq) -> Ordering {
    //     let diff = self.0.wrapping_sub(other.0) as i32;
    //     if diff < 0 {
    //         Ordering::Less
    //     } else if diff > 0 {
    //         Ordering::Greater
    //     } else {
    //         Ordering::Equal
    //     }
    // }
}

// TODO: implement 4 microsecond clock, and make this nice
pub fn new_isn(con: &TCPCon) -> u32 {
    let key: &[u8; 16] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let mut hasher = SipHasher13::new_with_key(key);

    TICK.load(std::sync::atomic::Ordering::Relaxed)
        .hash(&mut hasher);
    con.hash(&mut hasher);

    hasher.finish() as u32
}

impl From<u32> for Seq {
    fn from(value: u32) -> Self {
        Seq(value)
    }
}

impl Eq for Seq {}

impl PartialEq for Seq {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Ord for Seq {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.0.wrapping_sub(other.0) as i32).cmp(&0)
    }
}

impl PartialOrd for Seq {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

pub fn seq_lte(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

pub fn seq_gt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

pub fn seq_gte(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) >= 0
}
