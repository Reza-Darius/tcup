use std::net::IpAddr;

use crate::{
    eth::Mac,
    tap::device::{
        TAPDevice, TAPDeviceOptions, TAPStream,
        TapError::{self},
    },
    utils::packet::{ETH, IP, Packet},
};
use std::{collections::HashMap, net::Ipv4Addr};

use tracing::trace;

use crate::{eth::ARPTable, utils::packet::ARP};

use futures::StreamExt;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tracing::{error, instrument};

pub trait LinkService {
    type Sender: LinkSink + Clone;

    fn sender(&self) -> Self::Sender;
    fn recv(&mut self) -> Option<Packet<ETH>>;

    fn addr(&self) -> IpAddr;
    fn mac(&self) -> Mac;
}

pub trait LinkSink {
    type Error;
    async fn send_frame(&self, packet: Packet<ETH>) -> Result<(), Self::Error>;
    async fn send_frames(&self, packets: Vec<Packet<ETH>>) -> Result<(), Self::Error>;
}

pub enum TAPActorMessage {
    Packet(Packet<ETH>),
    Packets(Vec<Packet<ETH>>),
}

impl From<Packet<ETH>> for TAPActorMessage {
    fn from(value: Packet<ETH>) -> Self {
        TAPActorMessage::Packet(value)
    }
}

impl From<Vec<Packet<ETH>>> for TAPActorMessage {
    fn from(value: Vec<Packet<ETH>>) -> Self {
        TAPActorMessage::Packets(value)
    }
}

pub struct TAPActorHandle {
    pub addr: Option<IpAddr>,
    pub mac: Mac,
    sender: Sender<TAPActorMessage>,
    receiver: Receiver<Packet<ETH>>,
}

impl TAPActorHandle {
    /// initializes a new TAP device, panics if called more than once
    pub async fn new(
        name: impl Into<String>,
        opts: TAPDeviceOptions,
        buf_size: usize,
    ) -> Result<Self, TapError> {
        let tap = TAPDevice::new(name, opts).await?;
        let addr = tap.addr();
        let mac = tap.mac();
        let (msg_tx, msg_rx) = channel::<TAPActorMessage>(buf_size);
        let (packet_tx, packet_rx) = channel::<Packet<ETH>>(buf_size);

        let mut actor = TAPActor {
            tap: tap.into_stream(),
            receiver: msg_rx,
            sender: packet_tx,
        };

        tokio::spawn(async move { actor.run().await });

        Ok(TAPActorHandle {
            addr,
            mac,
            sender: msg_tx,
            receiver: packet_rx,
        })
    }

    pub fn sender(&self) -> Sender<TAPActorMessage> {
        self.sender.clone()
    }

    pub async fn recv(&mut self) -> Option<Packet<ETH>> {
        self.receiver.recv().await
    }
}

impl TAPActorHandle {
    pub async fn send(&self, msg: TAPActorMessage) {
        self.sender.send(msg).await.unwrap();
    }
}

pub struct TAPReceiver(Receiver<Packet<ETH>>);

impl TAPReceiver {
    pub async fn recv(&mut self) -> Packet<ETH> {
        self.0.recv().await.unwrap()
    }
}

pub struct TAPActor {
    tap: TAPStream,
    receiver: Receiver<TAPActorMessage>,
    sender: Sender<Packet<ETH>>,
}

impl TAPActor {
    #[instrument(name = "TAP_actor", skip_all)]
    async fn run(&mut self) {
        loop {
            tokio::select! {
                Some(res) = self.tap.next() => {
                    match res {
                        Err(e) if e.kind() != std::io::ErrorKind::InvalidData => {
                            error!(%e, "error when reading from stream");
                        },
                        Ok(packet) => {
                            self.sender.send(packet).await.expect("the receiver cant be closed");
                        },
                        _ => {}
                    };
                }
                Some(msg) = self.receiver.recv() => {
                    if let Err(e) = self.handle_message(msg).await {
                        error!(%e, "error when handling message");
                    };
                }
            }
        }
    }

    async fn handle_message(&mut self, msg: TAPActorMessage) -> Result<(), TapError> {
        match msg {
            TAPActorMessage::Packet(packet) => self.tap.send_frame(&packet).await,
            TAPActorMessage::Packets(packets) => self.tap.send_frames(&packets).await,
        }
    }
}

struct ARPStore {
    map: HashMap<Ipv4Addr, Mac>,
    if_addr: (Mac, Ipv4Addr),
}

impl ARPTable for ARPStore {
    fn update_if_present(&mut self, smac: Mac, sip: Ipv4Addr) -> bool {
        if let Some(entry) = self.map.get_mut(&sip) {
            *entry = smac;
            true
        } else {
            false
        }
    }

    fn insert(&mut self, smac: Mac, sip: Ipv4Addr) {
        self.map.insert(sip, smac);
    }

    fn addr(&self) -> (Mac, Ipv4Addr) {
        self.if_addr
    }
}

// TODO: retry pending arp requests
// TODO: deal with stale entries
pub struct ARPService {
    link_sink: Sender<TAPActorMessage>,
    arp_queue: HashMap<Ipv4Addr, Vec<Packet<IP>>>,
    store: ARPStore,
}

impl ARPService {
    pub fn new(if_mac: Mac, if_addr: Ipv4Addr, sender: Sender<TAPActorMessage>) -> Self {
        ARPService {
            link_sink: sender,
            arp_queue: HashMap::new(),
            store: ARPStore {
                map: HashMap::new(),
                if_addr: (if_mac, if_addr),
            },
        }
    }

    pub fn get_mac(&self, target_ip: Ipv4Addr) -> Option<Mac> {
        self.store.map.get(&target_ip).copied()
    }

    pub fn request_mac(&self, target_ip: Ipv4Addr) -> Packet<ETH> {
        Packet::<ARP>::new_request(self.store.if_addr.0, self.store.if_addr.1, target_ip)
    }

    pub async fn service_arp(&mut self, packet: Packet<ARP>) {
        if let Some(event) = packet.service(&mut self.store) {
            match event {
                crate::eth::ARPServiceResult::Reply(packet) => self.send_frame(packet).await,
                crate::eth::ARPServiceResult::Updated(ipv4_addr) => {
                    // check for queued up packets in case we updated an ARP entry
                    if let Some(waiting_packets) = self.check_queue(ipv4_addr) {
                        let mac = self.get_mac(ipv4_addr).expect("it needs to be there now");
                        for packet in waiting_packets {
                            let frame = packet.to_eth(mac, self.store.if_addr.0);
                            self.send_frame(frame).await;
                        }
                    }
                }
            }
        }
    }

    pub async fn service_ip(&mut self, packet: Packet<IP>) {
        if let Some(mac) = self.get_mac(packet.dip()) {
            let frame = packet.to_eth(mac, self.store.if_addr.0);
            self.send_frame(frame).await;
        } else {
            // we queue up pending packets
            let frame = self.request_mac(packet.dip());
            self.send_frame(frame).await;
            self.queue_packet(packet);
        }
    }

    fn queue_packet(&mut self, packet: Packet<IP>) {
        match self.arp_queue.entry(packet.dip()) {
            std::collections::hash_map::Entry::Occupied(mut occupied_entry) => {
                occupied_entry.get_mut().push(packet);
            }
            std::collections::hash_map::Entry::Vacant(vacant_entry) => {
                vacant_entry.insert(vec![packet]);
            }
        }
    }

    fn check_queue(&mut self, target_ip: Ipv4Addr) -> Option<Vec<Packet<IP>>> {
        self.arp_queue.remove(&target_ip)
    }

    async fn send_frame(&self, frame: Packet<ETH>) {
        self.link_sink
            .send(frame.into())
            .await
            .expect("the chan cant be closed");
    }
}
