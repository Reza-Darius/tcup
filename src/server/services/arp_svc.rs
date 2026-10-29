use crate::server::services::tap_svc::TAPActorMessage;
use crate::{eth::ARPTable, utils::packet::ARP};
use crate::{
    eth::Mac,
    utils::packet::{ETH, IP, Packet},
};
use std::{collections::HashMap, net::Ipv4Addr};

use tokio::sync::mpsc::{Receiver, Sender, channel};
use tracing::debug;

#[derive(Debug)]
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

#[derive(Clone)]
pub struct ARPServiceHandle {
    sender: Sender<ARPServiceMessage>,
}

impl ARPServiceHandle {
    pub async fn send(&self, msg: ARPServiceMessage) {
        self.sender.send(msg).await;
    }
}

#[derive(Debug)]
pub enum ARPServiceMessage {
    ARP(Packet<ARP>),
    IP(Packet<IP>),
}

impl From<Packet<ARP>> for ARPServiceMessage {
    fn from(value: Packet<ARP>) -> Self {
        ARPServiceMessage::ARP(value)
    }
}

impl From<Packet<IP>> for ARPServiceMessage {
    fn from(value: Packet<IP>) -> Self {
        ARPServiceMessage::IP(value)
    }
}

// TODO: retry pending arp requests
// TODO: deal with stale entries
#[derive(Debug)]
pub struct ARPService {
    link_sink: Sender<TAPActorMessage>,
    arp_queue: HashMap<Ipv4Addr, Vec<Packet<IP>>>,
    store: ARPStore,
}

impl ARPService {
    pub fn init(
        if_mac: Mac,
        if_addr: Ipv4Addr,
        sender: Sender<TAPActorMessage>,
    ) -> ARPServiceHandle {
        let (tx, rx) = channel(1024);

        let svc = ARPService {
            link_sink: sender,
            arp_queue: HashMap::new(),
            store: ARPStore {
                map: HashMap::new(),
                if_addr: (if_mac, if_addr),
            },
        };

        tokio::spawn(async move { svc.run(rx).await });

        ARPServiceHandle { sender: tx }
    }

    pub fn get_mac(&self, target_ip: Ipv4Addr) -> Option<Mac> {
        self.store.map.get(&target_ip).copied()
    }

    pub fn request_mac(&self, target_ip: Ipv4Addr) -> Packet<ETH> {
        Packet::<ARP>::new_request(self.store.if_addr.0, self.store.if_addr.1, target_ip)
    }

    async fn run(mut self, mut rx: Receiver<ARPServiceMessage>) {
        while let Some(msg) = rx.recv().await {
            match msg {
                ARPServiceMessage::ARP(packet) => self.service_arp(packet).await,
                ARPServiceMessage::IP(packet) => self.service_ip(packet).await,
            };
        }

        debug!("shutting down ARP service worker");
    }

    async fn service_arp(&mut self, packet: Packet<ARP>) {
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

    async fn service_ip(&mut self, packet: Packet<IP>) {
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
