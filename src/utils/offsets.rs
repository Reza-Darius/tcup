/// helper trait to slice into a buffer for network packet offsets
pub trait NetworkOffsets {
    fn eth_hdr(&self) -> &[u8];
    fn eth_hdr_mut(&self) -> &mut [u8];
    fn eth_pay(&self) -> &[u8];
    fn eth_pay_mut(&self) -> &mut [u8];

    fn ip_hdr(&self) -> &[u8];
    fn ip_hdr_mut(&self) -> &mut [u8];
    fn ip_pay(&self) -> &[u8];
    fn ip_pay_mut(&self) -> &mut [u8];

    fn tcp_hdr(&self) -> &[u8];
    fn tcp_hdr_mut(&self) -> &mut [u8];
    fn tcp_pay(&self) -> &[u8];
    fn tcp_pay_mut(&self) -> &mut [u8];
}

