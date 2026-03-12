struct ArpPacket {
    header: ArpHeader,
    payload: ArpIpv4,
}

#[repr(C, packed)]
struct ArpHeader {
    hwtype: u16,
    proto: u16,
    hwsize: u8,
    prosize: u8,
    opcode: u16,
}

#[repr(C, packed)]
struct ArpIpv4 {
    smac: [u8; 6],
    sip: u32,
    dmac: [u8; 6],
    dip: u32,
}
