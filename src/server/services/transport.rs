use std::{collections::HashMap, net::SocketAddrV4};

use slab::Slab;
use tokio::sync::mpsc::Sender;
use tracing::error;

use crate::{
    tcp::{
        TCPState,
        sock::{Socket, SocketMessage, TCPCall, TCPCon, no_socket_found},
    },
    utils::packet::{IP, Packet, TCP},
};

pub trait TransportService {
    async fn service_request(&mut self, call: TCPCall);
}

struct TCPServiceV1 {
    /// sender to dump outgoing IP packets into
    ip_svc: Sender<Packet<IP>>,

    /// connection table
    socket_table: Slab<Socket>,

    con_table: HashMap<TCPCon, usize>,
    listen_table: HashMap<SocketAddrV4, usize>,
}

impl TransportService for TCPServiceV1 {
    async fn service_request(&mut self, call: TCPCall) {
        match call {
            TCPCall::Connect(_) => todo!(),
            TCPCall::Listen(_) => todo!(),
            TCPCall::Close => todo!(),
            TCPCall::Send(items) => todo!(),
            TCPCall::Receive(sender) => todo!(),
            TCPCall::Segment(packet) => self.service_segment(packet).await,
        }
    }
}

impl TCPServiceV1 {
    pub fn new() -> Self {
        todo!()
    }

    async fn new_listen(&mut self, addr: SocketAddrV4) {
        let sock = Socket::listen(self.ip_svc.clone(), addr, 100);
        let key = self.socket_table.insert(sock);
        self.listen_table.insert(addr, key);
    }

    async fn service_segment(&mut self, segment: Packet<TCP>) {
        let con = segment.con();
        let addr = SocketAddrV4::new(con.remote_ip, con.remote_port);

        let Some(socket) = self
            .con_table
            .get(&con)
            .or_else(|| self.listen_table.get(&addr))
            .and_then(|&key| self.socket_table.get(key))
        else {
            no_socket_found(segment, &self.ip_svc).await;
            return;
        };

        match socket.call(SocketMessage::Segment(segment)).await {
            Ok(_) => {
                match socket.status().await {
                    TCPState::Closed => {
                        self.con_table.remove(&con);
                    }
                    TCPState::Listen => {
                        // move to listen table
                        let sock = self.con_table.remove(&con).unwrap();
                        self.listen_table
                            .insert(SocketAddrV4::new(con.remote_ip, con.remote_port), sock);
                    }
                    _ => {}
                }
            }
            Err(e) => error!(%e, "socket call error"),
        }
    }
}
