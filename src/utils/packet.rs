/*
* Top level definitions for packets
*/
use std::marker::PhantomData;

/// a packet generic over supported protocols
///
/// when transitioning between protocols, the buffer gets reused
#[derive(Debug, Clone)]
pub struct Packet<L: Prot> {
    pub data: Vec<u8>,
    l_type: PhantomData<L>,
}

impl<L: Prot> NetworkPacket for Packet<L> {
    fn len(&self) -> usize {
        self.data.len()
    }

    fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    fn into_vec(self) -> Vec<u8> {
        self.data
    }

    fn from_vec(data: Vec<u8>) -> Self {
        Packet{ data, l_type: PhantomData }
    }
}

impl<L: Prot> From<Vec<u8>> for Packet<L> {
    fn from(value: Vec<u8>) -> Self {
        Packet{ data: value, l_type: PhantomData }
    }
}

impl<L: Prot> AsRef<[u8]> for Packet<L> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

#[derive(Debug, Clone)]
pub enum EthPayload {
    Ip(Packet<Ipv4>),
    Arp(Packet<Arp>),
}

#[derive(Debug, Clone)]
pub enum Ipv4Payload {
    Tcp(Packet<Tcp>),
    Icmp(Packet<Icmp>),
}

/// marker trait for supported protocols
pub trait Prot {}

/// trait for a packet that can be sent on the network
pub trait NetworkPacket {
    fn len(&self) -> usize;
    fn as_bytes(&self) -> &[u8];
    fn into_vec(self) -> Vec<u8>;
    fn from_vec(data: Vec<u8>) -> Self;
}

#[derive(Debug, Clone, Copy)]
pub struct Eth;
impl Prot for Eth {}

#[derive(Debug, Clone, Copy)]
pub struct Arp;
impl Prot for Arp {}

#[derive(Debug, Clone, Copy)]
pub struct Ipv4;
impl Prot for Ipv4 {}

#[derive(Debug, Clone, Copy)]
pub struct Tcp;
impl Prot for Tcp {}

#[derive(Debug, Clone, Copy)]
pub struct Icmp;
impl Prot for Icmp {}
