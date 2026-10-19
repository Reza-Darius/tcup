use std::{collections::HashMap, net::Ipv4Addr};

use tracing::trace;

use crate::{
    eth::{ArpStore, Mac},
    utils::packet::{ARP, ETH, Packet},
};

struct ARPStore {
    map: HashMap<Ipv4Addr, Mac>,
    if_addr: (Mac, Ipv4Addr),
}

impl ArpStore for ARPStore {
    fn update_if_present(&mut self, smac: Mac, sip: Ipv4Addr) -> bool {
        match self.map.entry(sip) {
            std::collections::hash_map::Entry::Occupied(mut occupied_entry) => {
                occupied_entry.insert(smac);
                true
            }
            std::collections::hash_map::Entry::Vacant(_) => false,
        }
    }

    fn insert(&mut self, smac: Mac, sip: Ipv4Addr) {
        trace!(%smac, %sip, "arp store: inserting");
        self.map.insert(sip, smac);
    }

    fn addr(&self) -> (Mac, Ipv4Addr) {
        self.if_addr
    }
}

pub struct ARPService {
    store: ARPStore,
}

impl ARPService {
    pub fn new(if_mac: Mac, if_addr: Ipv4Addr) -> Self {
        ARPService {
            store: ARPStore {
                map: HashMap::new(),
                if_addr: (if_mac, if_addr),
            },
        }
    }

    pub fn handle_packet(&mut self, packet: Packet<ARP>) -> Option<Packet<ETH>> {
        packet.run_arp_check(&mut self.store)
    }
}
