use std::{
    collections::{BTreeSet, HashMap, VecDeque},
    net::SocketAddrV4,
};

use slab::Slab;
use tracing::{debug, error, instrument, trace};

use crate::{
    server::services::arp_svc::ARPServiceHandle,
    tcp::{
        TCPError, TCPState,
        socket::{Socket, TCPCall, TCPCon, no_socket_found},
    },
    utils::packet::{Packet, TCP},
};

pub trait TransportService {
    type Error;

    async fn service_request(&mut self, call: TCPCall) -> Result<(), Self::Error>;
}

pub struct TCPServiceV1 {
    /// sender to dump outgoing IP packets into
    out_svc: ARPServiceHandle,

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
            TCPCall::Receive((con, sender)) => {
                debug!("servicing receive call");

                if let Some(socket) = self
                    .con_table
                    .get(&con)
                    .and_then(|sock_id| self.socket_table.get(*sock_id))
                {
                    socket
                        .call(crate::tcp::socket::SocketMessage::Receive(sender))
                        .await
                } else {
                    Err(TCPError::SocketError("socket not found".into()))
                }
            }
            TCPCall::Segment(packet) => self.service_segment(packet).await,
        }
    }
}

impl TCPServiceV1 {
    pub fn new(out_svc: ARPServiceHandle) -> Self {
        Self {
            out_svc,
            socket_table: Slab::new(),
            con_table: HashMap::new(),
            listen_table: HashMap::new(),
            port_svc: PortService::new(),
        }
    }

    async fn new_listen(&mut self, addr: SocketAddrV4) -> Result<(), TCPError> {
        self.port_svc.register(addr.port())?;

        debug!(%addr, "new listening socket");

        let sock = Socket::listen(self.out_svc.clone(), addr, 100);
        let key = self.socket_table.insert(sock);
        self.listen_table.insert(addr, key);

        Ok(())
    }

    // OPTIMIZE: we are requesting the status for every submitted packet, no bueno!
    #[instrument(name = "TCPService", skip_all, fields(con = ?segment.con()))]
    async fn service_segment(&mut self, segment: Packet<TCP>) -> Result<(), TCPError> {
        let seg_con = segment.con();
        let listen_addr = SocketAddrV4::new(seg_con.local_ip, seg_con.local_port);

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
                    self.port_svc.free(seg_con.local_port);
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
            error!(%listen_addr, "no socket found");

            if let Some(resp) = no_socket_found(segment).await {
                self.out_svc.send(resp.into()).await;
            };
            return Err(TCPError::SocketError("no socket found".into()));
        };

        trace!("listening socket found");

        match listen_sock.send_seg(segment).await {
            // state didnt change
            TCPState::Listen => {}
            // going from listening to closed should probably not happen
            TCPState::Closed => {
                self.listen_table.remove(&listen_addr);
                self.port_svc.free(listen_addr.port());
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
///
/// OPTIMIZE: a bitmap approach is probably better
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

    fn register(&mut self, port: u16) -> Result<(), TCPError> {
        if !self.taken.insert(port) {
            Err(TCPError::SocketError("port already in use".into()))
        } else {
            Ok(())
        }
    }

    /// requests a free port, this function panics if U16::MAX - 1000 ports are occupied
    fn request(&mut self) -> u16 {
        if let Some(p) = self.freelist.pop_front() {
            return p;
        }

        if let Some(p) = self.taken.last().copied() {
            assert!((Self::LOWEST_PORT..u16::MAX).contains(&p));

            self.taken.insert(p + 1);
            p + 1
        } else {
            self.taken.insert(Self::LOWEST_PORT);
            Self::LOWEST_PORT
        }
    }

    /// returns port back to the pool
    fn free(&mut self, port: u16) {
        assert!(port >= Self::LOWEST_PORT);

        if let Some(last) = self.taken.last().copied()
            && last >= port
        {
            assert!(self.taken.remove(&port));
            self.freelist.push_back(port);
        }
    }

    fn is_taken(&self, port: u16) -> bool {
        self.taken.contains(&port)
    }
}
