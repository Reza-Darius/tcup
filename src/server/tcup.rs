use crate::{
    eth::{EthErr, EthPayload},
    ip::{IpErr, Ipv4Payload},
    server::services::{
        arp_svc::{ARPService, ARPServiceHandle},
        tap_svc::TAPServiceHandle,
        transport::{TCPServiceV1, TransportService},
    },
    tap::device::TAPDeviceOptions,
    tcp::socket::{TCPCall, TCPCon},
    utils::packet::{ETH, IP, Packet},
};
use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::sync::oneshot;
use tracing::{debug, error, info, instrument, warn};

pub async fn init(
    if_name: impl Into<String>,
    if_addr: (Ipv4Addr, u8),
    virt_addr: SocketAddrV4,
) -> Result<TCupHandle> {
    let (tx, rx) = channel(1024);
    let srv = TCupServer::new(if_name, if_addr, virt_addr, rx).await?;

    tokio::spawn(async move { srv.run().await });

    Ok(TCupHandle { sender: tx })
}

pub struct TCupHandle {
    sender: Sender<TCPCall>,
}

impl TCupHandle {
    pub async fn request_data(
        &self,
        virt_host: SocketAddrV4,
        client: SocketAddrV4,
    ) -> Result<oneshot::Receiver<Vec<u8>>> {
        let con = TCPCon {
            local_ip: *virt_host.ip(),
            local_port: virt_host.port(),
            remote_ip: *client.ip(),
            remote_port: client.port(),
        };
        let (tx, rx) = oneshot::channel();
        self.sender.send(TCPCall::Receive((con, tx))).await?;
        Ok(rx)
    }
}

struct TCupServer {
    virt_host: SocketAddrV4,

    link_svc: TAPServiceHandle,
    arp_svc: ARPServiceHandle,
    trans_svc: TCPServiceV1,

    user_chan: Receiver<TCPCall>,
}

impl TCupServer {
    async fn new(
        if_name: impl Into<String>,
        if_addr: (Ipv4Addr, u8),
        virt_addr: SocketAddrV4,
        rx: Receiver<TCPCall>,
    ) -> Result<Self> {
        let tap = TAPServiceHandle::new(
            if_name,
            TAPDeviceOptions {
                addr: Some((IpAddr::V4(if_addr.0), if_addr.1)),
            },
            512,
        )
        .await?;
        let arp = ARPService::init(tap.mac, *virt_addr.ip(), tap.sender());

        let mut tcp = TCPServiceV1::new(arp.clone());

        // create a test listening socket
        tcp.service_request(crate::tcp::socket::TCPCall::Listen(SocketAddrV4::new(
            *virt_addr.ip(),
            virt_addr.port(),
        )))
        .await?;

        Ok(TCupServer {
            virt_host: virt_addr,
            link_svc: tap,
            arp_svc: arp,
            trans_svc: tcp,
            user_chan: rx,
        })
    }

    async fn run(mut self) -> Result<()> {
        info!(if_mac = %self.link_svc.mac, if_addr = %self.link_svc.addr.unwrap(), "running server");

        loop {
            tokio::select! {
                link = self.link_svc.recv() => {
                    if let Some(packet) = link {
                        if let Err(e) = self.handle_inc_frame(packet).await {
                            check_err(e);
                        }
                    } else {
                        warn!("link service channel closed!");
                        break
                    }
                }
                user_call = self.user_chan.recv() => {
                    if let Some(call) = user_call {
                        self.trans_svc.service_request(call).await?
                    } else {
                        warn!("user input channel closed!");
                        break
                    }
                }
            }
        }
        info!("shutting down server");
        Ok(())
    }

    #[instrument(skip_all)]
    async fn handle_inc_frame(&mut self, packet: Packet<ETH>) -> Result<()> {
        let (hdr, payload) = packet.into_parts()?;

        debug!(eth_frame = %hdr);

        match payload {
            EthPayload::Arp(packet) => {
                self.arp_svc.send(packet.into()).await;
                debug!("sent ARP reply");
            }
            EthPayload::Ip(packet) => {
                self.handle_ip_packet(packet).await?;
            }
        };

        Ok(())
    }

    async fn handle_ip_packet(&mut self, packet: Packet<IP>) -> Result<()> {
        let (hdr, payload) = packet.into_parts()?;

        debug!(ip_packet = %hdr);

        // is this packet for us?
        if hdr.dip() != *self.virt_host.ip() {
            return Ok(());
        }

        match payload {
            Ipv4Payload::Icmp(packet) => {
                if let Some(reply) = packet.service(hdr.sip(), hdr.dip()) {
                    self.arp_svc.send(reply.into()).await;
                }
            }
            Ipv4Payload::Tcp(packet) => self.trans_svc.service_request(packet.into()).await?,
        };

        Ok(())
    }

    async fn recv_data(&mut self, addr: SocketAddrV4) -> Result<oneshot::Receiver<Vec<u8>>> {
        let con = TCPCon {
            local_ip: *self.virt_host.ip(),
            local_port: 4000,
            remote_ip: *addr.ip(),
            remote_port: addr.port(),
        };
        let (tx, rx) = oneshot::channel();
        self.trans_svc
            .service_request(TCPCall::Receive((con, tx)))
            .await?;
        Ok(rx)
    }
}

fn check_err(error: anyhow::Error) {
    if let Some(e) = error.downcast_ref::<EthErr>()
        && !matches!(e, EthErr::UnsupportedProtocol)
    {
        error!(%e, "error when handling packet");
    }
    if let Some(e) = error.downcast_ref::<IpErr>()
        && !matches!(e, IpErr::UnsupportedProtocol)
    {
        error!(%e, "error when handling packet");
    }
}
