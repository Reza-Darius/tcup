use std::collections::BTreeMap;

use crate::tcp::{error::TCPError, tcp_packet::TCP_SEG_MAX_SIZE};

#[derive(Debug, Default)]
pub struct SendBuf {
    data: Vec<u8>,
    /// counter from the left side to track popped data
    /// this should correspond to snd_nxt - snd_una
    count: usize,
}

impl SendBuf {
    pub fn new(cap: usize) -> Self {
        SendBuf {
            data: Vec::with_capacity(cap),
            count: 0,
        }
    }

    /// queue up data into the send buffer
    pub fn insert(&mut self, data: impl AsRef<[u8]>) -> Result<(), TCPError> {
        let d = data.as_ref();

        if d.len() + self.count >= self.data.capacity() {
            return Err(TCPError::BufferError("send buffer overflow".into()));
        }

        self.data.extend_from_slice(data.as_ref());
        Ok(())
    }

    /// retrieve N bytes of new data, does not move up the cursor
    /// never gives out more than TCP_SEG_MAX_SIZE bytes
    pub fn get_new_seg(&self, len: usize) -> Option<&[u8]> {
        if self.count == self.data.len() {
            return None;
        }

        assert!(self.count + len <= self.data.len());

        let lo = self.count;
        let hi = lo + usize::min(lo, TCP_SEG_MAX_SIZE);

        let out_slice = &self.data[lo..hi];
        Some(out_slice)
    }

    /// retreives data until cursor
    pub fn get_last_seg(&self) -> Option<&[u8]> {
        if self.data.is_empty() {
            return None;
        }

        let hi = usize::min(self.count, TCP_SEG_MAX_SIZE);
        Some(&self.data[0..hi])
    }

    /// mark len bytes as ACKd, moving up the cursor
    pub fn free_n(&mut self, len: usize) {
        assert!(self.count + len <= self.data.len());
        self.count += len;
        if self.count == self.data.len() {
            self.clear();
        }
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    fn clear(&mut self) {
        if self.count == self.data.len() {
            self.data.clear();
            self.count = 0;
        }
    }
}

#[derive(Debug)]
pub struct RecvBuf {
    // sequence numbers dont implement Ord so we have to calculate the idx against a stable base
    // we rely on the invariance that we never buffer more than u32::MAX amount of data
    base: u32,
    data: BTreeMap<u32, Vec<u8>>,
}

impl RecvBuf {
    pub fn new(_: usize) -> Self {
        RecvBuf {
            base: 0,
            data: BTreeMap::new(),
        }
    }

    fn key(&self, seq: u32) -> u32 {
        seq.wrapping_sub(self.base)
    }

    pub fn insert(&mut self, data: impl AsRef<[u8]>, seq: u32) {
        if self.data.is_empty() {
            self.base = seq;
        }

        match self.data.entry(self.key(seq)) {
            std::collections::btree_map::Entry::Vacant(vacant_entry) => {
                vacant_entry.insert_entry(data.as_ref().to_vec());
            }
            std::collections::btree_map::Entry::Occupied(mut occupied_entry) => {
                let data = data.as_ref();
                if occupied_entry.get().len() < data.len() {
                    occupied_entry.insert(data.to_vec());
                };
            }
        };
    }

    pub fn pop_first(&mut self) -> Option<Vec<u8>> {
        self.data
            .first_key_value()
            .map(|entry| *entry.0)
            .and_then(|seg| self.pop(seg))
    }

    pub fn pop(&mut self, seq: u32) -> Option<Vec<u8>> {
        if self.data.is_empty() {
            return None;
        }

        let idx = self.key(seq);
        let mut data = self.data.remove(&idx)?;
        let mut clean_up = Vec::new();

        // we loop through the map such that we assemble one byte vector
        // segments and their associated data might overlap so we have to account for that
        for entry in self.data.iter() {
            let e_seg = *entry.0;
            let lo = idx;
            let hi = idx + data.len() as u32;
            if e_seg >= lo && e_seg <= hi {
                clean_up.push(e_seg);

                if e_seg + entry.1.len() as u32 > hi {
                    let dif = hi - e_seg;
                    data.truncate(data.len() - dif as usize);
                    data.extend_from_slice(entry.1);
                }
                // in case of fully contained segments we can remove it without extending data
            }
        }

        // we have to do this cause the above loop borrows the map immutably ugh
        for n in clean_up.iter() {
            self.data.remove(n);
        }

        Some(data)
    }

    /// seq number of the first entry
    pub fn seq_first(&self) -> Option<u32> {
        self.data
            .first_key_value()
            .map(|entry| self.base.wrapping_add(*entry.0))
    }

    pub fn clear(&mut self) {
        self.data.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::RecvBuf;

    #[test]
    fn pop_single_segment() {
        let mut buf = RecvBuf::new(1024);
        buf.insert(b"hello", 100);

        assert_eq!(buf.pop(100), Some(b"hello".to_vec()));
        assert_eq!(buf.pop(100), None);
    }

    #[test]
    fn merge_out_of_order_segments() {
        let mut buf = RecvBuf::new(1024);

        // The first insertion establishes the reference sequence.
        buf.insert(b"abc", 100);
        buf.insert(b"ghi", 106);
        buf.insert(b"def", 103);

        assert_eq!(buf.pop(100), Some(b"abcdefghi".to_vec()));
        assert_eq!(buf.seq_first(), None);
    }

    #[test]
    fn merge_overlapping_segments() {
        let mut buf = RecvBuf::new(1024);

        buf.insert(b"abcdef", 100);
        buf.insert(b"defghi", 103);

        assert_eq!(buf.pop(100), Some(b"abcdefghi".to_vec()));
    }

    #[test]
    fn discard_fully_contained_segments() {
        let mut buf = RecvBuf::new(1024);

        buf.insert(b"abcdefghij", 100);
        buf.insert(b"def", 103);
        buf.insert(b"fgh", 105);

        assert_eq!(buf.pop(100), Some(b"abcdefghij".to_vec()));
        assert_eq!(buf.seq_first(), None);
    }

    #[test]
    fn merge_chained_overlaps() {
        let mut buf = RecvBuf::new(1024);

        buf.insert(b"abcdef", 100);
        buf.insert(b"efghij", 104);
        buf.insert(b"jklm", 109);

        assert_eq!(buf.pop(100), Some(b"abcdefghijklm".to_vec()));
    }

    #[test]
    fn do_not_merge_across_gaps() {
        let mut buf = RecvBuf::new(1024);

        buf.insert(b"abc", 100);
        buf.insert(b"ghi", 106);

        assert_eq!(buf.pop(100), Some(b"abc".to_vec()));
        assert_eq!(buf.seq_first(), Some(106));

        // rcv_nxt points to a missing segment.
        assert_eq!(buf.pop(103), None);

        // Inserting the missing segment makes the remaining data contiguous.
        buf.insert(b"def", 103);

        assert_eq!(buf.pop(103), Some(b"defghi".to_vec()));
        assert_eq!(buf.seq_first(), None);
    }

    #[test]
    fn seq_first_returns_sequence_number_not_offset() {
        let mut buf = RecvBuf::new(1024);

        buf.insert(b"abc", 100);
        buf.insert(b"xyz", 110);
        buf.insert(b"def", 103);

        assert_eq!(buf.seq_first(), Some(100));

        assert_eq!(buf.pop(100), Some(b"abcdef".to_vec()));
        assert_eq!(buf.seq_first(), Some(110));
    }

    #[test]
    fn handle_sequence_number_wraparound() {
        let mut buf = RecvBuf::new(1024);
        let base = u32::MAX - 2;

        // Three bytes occupy sequence numbers MAX-2, MAX-1 and MAX.
        // The next byte begins at sequence number 0.
        buf.insert(b"abc", base);
        buf.insert(b"def", 0);

        assert_eq!(buf.pop(base), Some(b"abcdef".to_vec()));
    }

    #[test]
    fn clear_discards_all_segments() {
        let mut buf = RecvBuf::new(1024);

        buf.insert(b"abc", 100);
        buf.insert(b"def", 103);

        buf.clear();

        assert_eq!(buf.seq_first(), None);
        assert_eq!(buf.pop(100), None);

        // The buffer can establish a new reference sequence.
        buf.insert(b"xyz", 500);

        assert_eq!(buf.seq_first(), Some(500));
        assert_eq!(buf.pop(500), Some(b"xyz".to_vec()));
    }

    #[test]
    fn merge_segments_across_u32_wraparound() {
        let mut buf = RecvBuf::new(1024);
        let base = u32::MAX - 2;

        buf.insert(b"abc", base);
        buf.insert(b"ghi", 3); // After wraparound
        buf.insert(b"def", 0);

        assert_eq!(buf.seq_first(), Some(base));
        assert_eq!(buf.pop(base), Some(b"abcdefghi".to_vec()));
        assert_eq!(buf.seq_first(), None);
    }
}
