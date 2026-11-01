use std::net::Ipv4Addr;

use crate::{
    eth::Mac,
    utils::packet::{ETH, Packet},
};

pub trait LinkService {
    type Handle: LVL2PacketSink + Clone + Send;

    fn sender(&self) -> Self::Handle;
    fn recv(&mut self) -> impl std::future::Future<Output = Packet<ETH>> + Send + 'static;

    fn addr(&self) -> Option<Ipv4Addr>;
    fn mac(&self) -> Mac;
}

pub trait LVL2PacketSink {
    type Error;
    fn service_packet(
        &self,
        packet: Packet<ETH>,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send + 'static;
    fn service_packet_batch(
        &self,
        packets: impl Iterator<Item = Packet<ETH>>,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send + 'static;
}
