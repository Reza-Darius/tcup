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
    fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// a slice to the entire packet buffer
    fn as_slice_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// unwrap the packet to the underlying buffer
    fn into_vec(self) -> Vec<u8> {
        self.data
    }

    /// unsafe conversion, reserved parsing functions
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

/// trait for a packet that can be sent on the network
pub trait PacketBuf {
    fn as_slice(&self) -> &[u8];
    fn as_slice_mut(&mut self) -> &mut [u8];
    fn into_vec(self) -> Vec<u8>;
    fn from_vec(data: Vec<u8>) -> Self;

    fn len(&self) -> usize {
        self.as_slice().len()
    }
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub trait NetworkPacket
where
    Self: Sized,
    Self::Error: std::error::Error,
{
    type Header;
    type Payload;
    type Error;

    /// parses a buffer, returning the packet on success
    fn parse(data: impl Into<Vec<u8>>) -> Result<Self, Self::Error>;

    /// build a new packet
    fn build(header: Self::Header, payload: Self::Payload) -> Self;

    /// splits up a packet into a lower-level packet
    ///
    /// this will call [`NetworkPacket::parse()`] on the underlying packet
    fn into_parts(self) -> Result<(Self::Header, Self::Payload), Self::Error>;

    fn header(&self) -> &Self::Header;
    fn payload(&self) -> &[u8];
}

/// marker trait for supported protocols
pub trait PacketType {}

#[derive(Debug, Clone, Copy)]
pub struct Eth;
impl PacketType for Eth {}

#[derive(Debug, Clone, Copy)]
pub struct Arp;
impl PacketType for Arp {}

#[derive(Debug, Clone, Copy)]
pub struct Ipv4;
impl PacketType for Ipv4 {}

#[derive(Debug, Clone, Copy)]
pub struct Tcp;
impl PacketType for Tcp {}

#[derive(Debug, Clone, Copy)]
pub struct Icmp;
impl PacketType for Icmp {}
