use bytemuck::{Pod, Zeroable};

use crate::error::Result;
use crate::tcp::{TCP_HDR_MAXSIZE, TCP_HDR_MINSIZE, TCPFlags};

#[derive(Debug, Clone, Copy, Pod, Zeroable, Default)]
#[repr(C, packed)]
pub struct TCP_hdr {
    pub sport: u16, // source port
    pub dport: u16, // destination port
    pub seq: u32,
    pub ack: u32,
    /// len of the header including options, first 4 bits
    pub len: u8,
    pub flags: TCPFlags,
    pub win_size: u16,
    pub check: u16,
    /// ignored in modern stacks
    pub urg_ptr: u16,
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

    pub fn set_len(&mut self, len: usize) -> Result<()> {
        if !(TCP_HDR_MINSIZE..=TCP_HDR_MAXSIZE).contains(&len) {
            return Err("len invalid for TCP header".into());
        }
        self.len = (((len >> 2) & 0xF) << 4) as u8;
        Ok(())
    }

    /// doff - data offset
    pub fn len(&self) -> usize {
        (((self.len >> 4) & 0xF) << 2) as usize
    }

    pub fn syn_only(&self) -> bool {
        self.flags == TCPFlags::SYN
    }

    pub fn check_syn(&self) -> bool {
        self.flags & TCPFlags::SYN == TCPFlags::SYN
    }

    pub fn set_syn(&mut self) -> &mut Self {
        self.flags |= TCPFlags::SYN;
        self
    }

    pub fn set_ack(&mut self) -> &mut Self {
        self.flags |= TCPFlags::ACK;
        self
    }

    pub fn check_ack(&self) -> bool {
        self.flags & TCPFlags::ACK == TCPFlags::ACK
    }

    pub fn check_synack(&self) -> bool {
        self.check_ack() && self.check_syn()
    }
}

impl std::fmt::Display for TCP_hdr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sport = self.sport;
        let dport = self.dport;
        let seq = self.seq;
        let ack = self.ack;
        let len = self.len();
        let win_size = self.win_size;
        let check = self.check;
        let urg_ptr = self.urg_ptr;
        let flags = self.flags;

        let hdr_bytes = (len >> 4) as u16 * 4;

        let active_flags: Vec<&str> = [
            (TCPFlags::CWR, "CWR"),
            (TCPFlags::ECE, "ECE"),
            (TCPFlags::URG, "URG"),
            (TCPFlags::ACK, "ACK"),
            (TCPFlags::PSH, "PSH"),
            (TCPFlags::RST, "RST"),
            (TCPFlags::SYN, "SYN"),
            (TCPFlags::FIN, "FIN"),
        ]
        .iter()
        .filter_map(|(flag, name)| {
            if flags.contains(*flag) {
                Some(*name)
            } else {
                None
            }
        })
        .collect();

        writeln!(f, "┌─────────────────┬───────────────────┐")?;
        writeln!(f, "│ {:<15} │ {:<17} │", "Field", "Value")?;
        writeln!(f, "├─────────────────┼───────────────────┤")?;
        writeln!(f, "│ {:<15} │ {:<17} │", "src port", sport)?;
        writeln!(f, "│ {:<15} │ {:<17} │", "dst port", dport)?;
        writeln!(f, "│ {:<15} │ {:#010x}        │", "seq", seq)?;
        writeln!(f, "│ {:<15} │ {:#010x}        │", "ack", ack)?;
        writeln!(f, "│ {:<15} │ {:<17} │", "header len", len)?;
        writeln!(f, "│ {:<15} │ {:<17} │", "window", win_size)?;
        writeln!(f, "│ {:<15} │ {:#06x}            │", "checksum", check)?;
        writeln!(f, "│ {:<15} │ {:<17} │", "urgent ptr", urg_ptr)?;
        writeln!(f, "├─────────────────┼───────────────────┤")?;
        writeln!(f, "│ {:<15} │ {:<17} │", "flags", active_flags.join(", "))?;
        write!(f, "└─────────────────┴───────────────────┘")
    }
}
