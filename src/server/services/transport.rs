use std::collections::HashMap;

use tokio::sync::mpsc::Sender;

use crate::{
    tcp::sock::{SocketCall, TCBMessage, TCPCon},
    utils::packet::{IP, Packet, TCP},
};

pub trait TransportService {
    fn service_packet(&mut self, packet: Packet<TCP>);
    fn service_user_req(&mut self, call: SocketCall);
}

struct TCPServiceV1 {
    /// sender to dump IP packets into for further processing
    ip_svc: Sender<Packet<IP>>,
    /// connection table
    con_table: HashMap<TCPCon, Sender<TCBMessage>>,
}
