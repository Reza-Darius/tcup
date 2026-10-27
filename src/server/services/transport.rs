use std::{collections::HashMap, net::SocketAddrV4};

use tokio::sync::mpsc::Sender;
use tracing::error;

use crate::{
    tcp::sock::{Socket, SocketMessage, TCPCall, TCPCon, no_socket_found},
    utils::packet::{IP, Packet, TCP},
};

pub trait TransportService {
    async fn service_request(&mut self, call: TCPCall);
}

struct TCPServiceV1 {
    /// sender to dump outgoing IP packets into
    ip_svc: Sender<Packet<IP>>,

    /// connection table
    con_table: HashMap<TCPCon, Socket>,
    listen_table: HashMap<SocketAddrV4, Socket>,
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
    async fn new_listen(&mut self, addr: SocketAddrV4) {
        let sock = Socket::listen(self.ip_svc.clone(), addr, 100);
        self.listen_table.insert(addr, sock);
    }

    async fn service_segment(&mut self, segment: Packet<TCP>) {
        let con = segment.con();

        if let Some(socket) = self.con_table.get(&con) {
            if socket.is_closed() {
                no_socket_found(segment, &self.ip_svc).await;
                self.con_table.remove(&con);
            } else if let Err(e) = socket.call(SocketMessage::Segment(segment)).await {
                error!(%e, "socket call error");
            };
        } else {
            no_socket_found(segment, &self.ip_svc).await;
        }
    }
}
