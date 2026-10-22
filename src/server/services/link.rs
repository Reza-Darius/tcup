use std::net::IpAddr;

use crate::{
    eth::Mac,
    utils::packet::{IP, Packet},
};

pub trait LinkService {
    type Sender: PacketSink + Clone;

    fn sender(&self) -> Self::Sender;
    async fn recv(&mut self) -> Packet<IP>;

    fn addr(&self) -> IpAddr;
    fn mac(&self) -> Mac;
}

pub trait PacketSink {
    type Error;
    async fn service_packet(&self, packet: Packet<IP>) -> Result<(), Self::Error>;
    async fn service_packet_batch(&self, packets: Vec<Packet<IP>>) -> Result<(), Self::Error>;
}

// pub struct TAPLinkServiceHandle {
//     pub addr: Option<IpAddr>,
//     pub mac: Mac,
//     sender: Sender<TAPLinkServiceMessage>,
//     receiver: Receiver<Packet<IP>>,
// }
//
// pub enum TAPLinkServiceMessage {
//     Packet(Packet<IP>),
//     Packets(Vec<Packet<IP>>),
// }
//
// pub struct TAPLinkService{
//     tap: TAPActorHandle,
//     arp: ARPService,
// }
