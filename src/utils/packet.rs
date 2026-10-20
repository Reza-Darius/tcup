/*
* Top level definitions for packets
*/
use std::marker::PhantomData;

/// a packet generic over supported protocols
///
/// when transitioning between protocols, the buffer gets reused
#[derive(Debug, Clone)]
pub struct Packet<P: PacketType> {
    data: Vec<u8>,
    l_type: PhantomData<P>,
}

impl<P: PacketType> PacketBuf for Packet<P> {
    /// a slice to the entire packet buffer
    #[inline(always)]
    fn as_buf(&self) -> &[u8] {
        &self.data
    }

    /// a slice to the entire packet buffer
    #[inline(always)]
    fn as_buf_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// unwrap the packet to the underlying buffer
    #[inline(always)]
    fn into_buf(self) -> Vec<u8> {
        self.data
    }

    /// unsafe conversion, reserved parsing functions
    #[inline(always)]
    fn from_vec(data: Vec<u8>) -> Self {
        Packet {
            data,
            l_type: PhantomData,
        }
    }
}

impl<P: PacketType> From<Vec<u8>> for Packet<P> {
    fn from(value: Vec<u8>) -> Self {
        Packet {
            data: value,
            l_type: PhantomData,
        }
    }
}

impl<P: PacketType> AsRef<[u8]> for Packet<P> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

/// trait for the underlying buffer of a packet
pub trait PacketBuf {
    fn as_buf(&self) -> &[u8];
    fn as_buf_mut(&mut self) -> &mut [u8];
    fn into_buf(self) -> Vec<u8>;
    fn from_vec(data: Vec<u8>) -> Self;

    fn len(&self) -> usize {
        self.as_buf().len()
    }
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub trait NetworkPacket<Packet>
where
    Self: Sized,
    Self::Error: std::error::Error,
{
    type Header;
    type Payload;
    type Error;

    /// parses a buffer, returning the packet on success
    fn parse(data: Packet) -> Result<Self, Self::Error>;

    /// build a new packet
    fn build(header: Self::Header, payload: Self::Payload) -> Self;

    /// splits up a packet into a lower-level packet
    ///
    /// this fucntion will generally call [`NetworkPacket::parse()`] on the underlying packet
    fn into_parts(self) -> Result<(Self::Header, Self::Payload), Self::Error>;

    fn hdr(&self) -> &Self::Header;
    fn payload(&self) -> &[u8];
}

/// marker trait for supported protocols
pub trait PacketType {}

#[derive(Debug, Clone, Copy)]
pub struct ETH;
impl PacketType for ETH {}

#[derive(Debug, Clone, Copy)]
pub struct ARP;
impl PacketType for ARP {}

#[derive(Debug, Clone, Copy)]
pub struct IP;
impl PacketType for IP {}

#[derive(Debug, Clone, Copy)]
pub struct TCP;
impl PacketType for TCP {}

#[derive(Debug, Clone, Copy)]
pub struct ICMP;
impl PacketType for ICMP {}
