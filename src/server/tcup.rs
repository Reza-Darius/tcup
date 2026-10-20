use std::net::{IpAddr, Ipv4Addr};

use crate::{
    eth::{ARPService, EthPayload},
    ip::Ipv4Payload,
    server::link::TAPActorHandle,
    tap::device::TAPDeviceOptions,
    utils::packet::{ETH, IP, Packet},
};
use anyhow::Result;
use tracing::{debug, error, info, instrument};

pub struct TcupServer {
    virt_host: Ipv4Addr,
    link_svc: TAPActorHandle,
    arp_svc: ARPService,
}

impl TcupServer {
    pub async fn new(
        if_name: impl Into<String>,
        if_addr: (Ipv4Addr, u8),
        virt_addr: Ipv4Addr,
    ) -> Result<Self> {
        let tap = TAPActorHandle::new(
            if_name,
            TAPDeviceOptions {
                addr: Some((IpAddr::V4(if_addr.0), if_addr.1)),
            },
            512,
        )
        .await?;
        let arp = ARPService::new(tap.mac, virt_addr);

        Ok(TcupServer {
            virt_host: virt_addr,
            link_svc: tap,
            arp_svc: arp,
        })
    }

    pub async fn run(mut self) -> Result<()> {
        info!(if_mac = %self.link_svc.mac, if_addr = %self.link_svc.addr.unwrap(), "running server");

        while let Some(packet) = self.link_svc.recv().await {
            if let Err(e) = self.handle_inc(packet).await {
                error!(%e, "error when handling packet");
            }
        }

        info!("shutting down server");
        Ok(())
    }

    #[instrument(skip_all)]
    async fn handle_inc(&mut self, packet: Packet<ETH>) -> Result<()> {
        let (hdr, payload) = packet.into_parts()?;

        debug!(eth_frame = %hdr);

        match payload {
            EthPayload::Arp(packet) => {
                // TODO: maybe check a waiting IP queue here?
                if let Some(reply) = self.arp_svc.handle_packet(packet) {
                    self.link_svc.send(reply.into()).await;
                    debug!("sent ARP reply");
                };
            }
            EthPayload::Ip(packet) => {
                self.handle_ip_packet(packet).await?;
            }
        };

        Ok(())
    }

    async fn handle_ip_packet(&mut self, packet: Packet<IP>) -> Result<()> {
        let (hdr, payload) = packet.into_parts()?;

        // is this packet for us?

        debug!(ip_packet = %hdr);

        match payload {
            Ipv4Payload::Icmp(packet) => {
                if let Some(reply) = packet.service(hdr.sip(), hdr.dip()) {
                    // do we have an address?
                    if let Some(mac_addr) = self.arp_svc.get_mac(hdr.sip()) {
                        // if yes, build eth frame and send it
                        let frame = Packet::<ETH>::new(mac_addr, self.link_svc.mac, reply.into());
                        self.link_svc.send(frame.into()).await;
                        debug!("ICMP reply sent");
                    } else {
                        // if no, queue up the packet and send an arp request
                        let arp_req = self.arp_svc.request_mac(hdr.sip());
                        self.link_svc.send(arp_req.into()).await;
                    }
                }
            }
            Ipv4Payload::Tcp(packet) => unimplemented!(),
        };

        Ok(())
    }
}
