use std::net::Ipv4Addr;

use anyhow::Result;
use crate::{eth::ARPService, server::link::TAPActorHandle};

pub struct TcupServer {
    link: TAPActorHandle,
    arp: ARPService,
}

impl TcupServer {
    pub fn new(name: impl Into<String>, addr: Ipv4Addr) -> Result<Self> {
        todo!()
    }

    pub async fn run(self) -> Result<()> {
        Ok(())
    }
}
