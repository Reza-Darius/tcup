use std::collections::HashMap;

use tokio::sync::mpsc::Sender;

use crate::{
    tcp::sock::{Socket, TCPCall, TCPCon},
    utils::packet::{IP, Packet, TCP},
};

pub trait TransportService {
    fn service_request(&mut self, call: TCPCall);
}

struct TCPServiceV1 {
    /// sender to dump outgoing IP packets into
    ip_svc: Sender<Packet<IP>>,

    /// connection table
    con_table: HashMap<TCPCon, Socket>,
}

impl TransportService for TCPServiceV1 {
    fn service_request(&mut self, call: TCPCall) {
        match call {
            TCPCall::Connect(_) => todo!(),
            TCPCall::Listen(_) => todo!(),
            TCPCall::Close => todo!(),
            TCPCall::Send(items) => todo!(),
            TCPCall::Receive(sender) => todo!(),
            TCPCall::Segment(packet) => todo!(),
        }
    }
}

impl TCPServiceV1 {
    fn service_segment(&self, segment: Packet<TCP>) {
        // - check connection table
        // - if connection found,
        //      if socket is not closed
        //          send the segment to socket
        // - else send reset
    }
}
