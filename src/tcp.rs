use bytemuck::{Pod, Zeroable};

pub const TCP_HDR_MINSIZE: usize = 20;

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C, packed)]
pub struct TCP_hdr {
    sport: u16, // source port
    dport: u16, // destination port

    seq: u32,
    ack: u32,

    len: u8, // first 4 bits, last 4 bits are reserved
    flags: u8,
    win_size: u16,
    check: u16,
    urg_ptr: u16,
}

impl TCP_hdr {
    pub fn from_be_bytes(data: &[u8; TCP_HDR_MINSIZE]) -> Self {
        let mut hdr: TCP_hdr = bytemuck::cast(*data);
        hdr.sport = u16::from_be(hdr.sport);
        hdr.dport = u16::from_be(hdr.dport);

        hdr.seq = u32::from_be(hdr.seq);
        hdr.ack = u32::from_be(hdr.ack);

        hdr.win_size = u16::from_be(hdr.win_size);
        hdr.urg_ptr = u16::from_be(hdr.urg_ptr);

        hdr
    }

    pub fn into_be_bytes(mut self) -> [u8; TCP_HDR_MINSIZE] {
        self.sport = u16::to_be(self.sport);
        self.dport = u16::to_be(self.dport);

        self.seq = u32::to_be(self.seq);
        self.ack = u32::to_be(self.ack);

        self.win_size = u16::to_be(self.win_size);
        self.urg_ptr = u16::to_be(self.urg_ptr);

        bytemuck::cast(self)
    }

    pub fn set_len(&mut self, len: usize) {}

    pub fn len(&self) -> usize {
        0
    }
}
