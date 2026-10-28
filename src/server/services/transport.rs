use std::{
    collections::{BTreeSet, HashMap, VecDeque},
    net::SocketAddrV4,
};

use slab::Slab;
use tokio::sync::mpsc::Sender;
use tracing::{debug, error, instrument, trace};

use crate::{
    tcp::{
        TCPError, TCPState,
        sock::{Socket, TCPCall, TCPCon, no_socket_found},
    },
    utils::packet::{IP, Packet, TCP},
};

pub trait TransportService {
    type Error;

    async fn service_request(&mut self, call: TCPCall) -> Result<(), Self::Error>;
}

struct TCPServiceV1 {
    /// sender to dump outgoing IP packets into
    ip_svc: Sender<Packet<IP>>,

    socket_table: Slab<Socket>,

    /// active connections
    con_table: HashMap<TCPCon, usize>,

    /// sockets in LISTEN state
    listen_table: HashMap<SocketAddrV4, usize>,

    port_svc: PortService,
}

impl TransportService for TCPServiceV1 {
    type Error = TCPError;

    async fn service_request(&mut self, call: TCPCall) -> Result<(), TCPError> {
        match call {
            TCPCall::Connect(_) => todo!(),
            TCPCall::Listen(addr) => self.new_listen(addr).await,
            TCPCall::Close => todo!(),
            TCPCall::Send(items) => todo!(),
            TCPCall::Receive(sender) => todo!(),
            TCPCall::Segment(packet) => self.service_segment(packet).await,
        }
    }
}

impl TCPServiceV1 {
    pub fn new(ip_svc: Sender<Packet<IP>>) -> Self {
        Self {
            ip_svc,
            socket_table: Slab::new(),
            con_table: HashMap::new(),
            listen_table: HashMap::new(),
            port_svc: PortService::new(),
        }
    }

    async fn new_listen(&mut self, addr: SocketAddrV4) -> Result<(), TCPError> {
        if self.port_svc.is_taken(addr.port()) {
            return Err(TCPError::SocketError("port already in use".into()));
        }

        debug!(%addr, "new listening socket");

        let sock = Socket::listen(self.ip_svc.clone(), addr, 100);
        let key = self.socket_table.insert(sock);
        self.listen_table.insert(addr, key);

        Ok(())
    }

    #[instrument(skip_all, fields(con = ?segment.con()))]
    async fn service_segment(&mut self, segment: Packet<TCP>) -> Result<(), TCPError> {
        let seg_con = segment.con();
        let listen_addr = SocketAddrV4::new(seg_con.remote_ip, seg_con.remote_port);

        // check for established connection
        if let Some(con_sock) = self
            .con_table
            .get(&seg_con)
            .and_then(|&key| self.socket_table.get(key))
        {
            trace!("connection found");
            match con_sock.send_seg(segment).await {
                TCPState::Listen => {
                    let s = self.con_table.remove(&seg_con).expect("we know its there");
                    self.listen_table.insert(listen_addr, s);
                }
                TCPState::Closed => {
                    self.con_table.remove(&seg_con);
                    self.port_svc.free_port(seg_con.remote_port);
                }
                _ => {}
            }
            return Ok(());
        }

        // check for a listening socket
        let Some(listen_sock) = self
            .listen_table
            .get(&listen_addr)
            .and_then(|&key| self.socket_table.get(key))
        else {
            error!("no socket found");

            no_socket_found(segment, &self.ip_svc).await;
            return Err(TCPError::SocketError("no socket found".into()));
        };

        trace!("listening socket found");

        match listen_sock.send_seg(segment).await {
            // state didnt change
            TCPState::Listen => {}
            // going from listening to closed should probably not happen
            TCPState::Closed => {
                self.listen_table.remove(&listen_addr);
                self.port_svc.free_port(listen_addr.port());
            }
            // move from listening to connection table
            TCPState::SynReceived => {
                let s = self
                    .listen_table
                    .remove(&listen_addr)
                    .expect("we know its there");
                self.con_table.insert(seg_con, s);
            }
            _ => unreachable!("no other state change can occur"),
        }

        Ok(())
    }
}

/// This service manages occupied and free ports
struct PortService {
    freelist: VecDeque<u16>,
    taken: BTreeSet<u16>,
}

impl PortService {
    const LOWEST_PORT: u16 = 1000;

    fn new() -> Self {
        PortService {
            freelist: VecDeque::new(),
            taken: BTreeSet::new(),
        }
    }

    fn request_port(&mut self) -> u16 {
        if let Some(p) = self.freelist.pop_front() {
            return p;
        }

        if let Some(p) = self.taken.last().copied() {
            assert!(p < u16::MAX);

            self.taken.insert(p + 1);
            return p + 1;
        }

        self.taken.insert(Self::LOWEST_PORT);
        Self::LOWEST_PORT
    }

    fn free_port(&mut self, port: u16) {
        assert!(port >= Self::LOWEST_PORT);
        assert!(self.taken.remove(&port));

        self.freelist.push_back(port);
    }

    fn is_taken(&self, port: u16) -> bool {
        self.taken.contains(&port)
    }
}
