/*
 A segment on the retransmission queue is fully acknowledged if the sum of its sequence number and length is less than or equal to the acknowledgment value in the incoming segment.

 Only segments that advance SND.NXT (i.e., consume sequence space) are tracked for retransmission.
*/

use std::collections::VecDeque;

/// retransmission queue
#[derive(Debug, Default)]
pub struct RTQ {
    q: VecDeque<RTQEntry>,
}

impl RTQ {
    pub fn new() -> Self {
        RTQ { q: VecDeque::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.q.is_empty()
    }

    pub fn push(&mut self, elem: RTQEntry) {
        self.q.push_back(elem);
    }
    pub fn pop(&mut self) -> Option<RTQEntry> {
        self.q.pop_front()
    }
    pub fn peek(&self) -> Option<&RTQEntry> {
        self.q.front()
    }
    pub fn match_front(&self, seg: u32) -> bool {
        if let Some(elem) = self.peek() {
            return elem.seq == seg;
        }
        false
    }
}

#[derive(Debug, Default)]
pub struct RTQEntry {
    pub seq: u32,
    pub len: u16,
}
