use std::{
    collections::{BTreeSet, HashMap, VecDeque},
    net::{Ipv4Addr, SocketAddrV4},
};

use slab::Slab;
use tokio::sync::oneshot;
use tracing::{debug, error, instrument, trace, warn};

use crate::{
    server::services::arp_svc::ARPServiceHandle,
    tcp::{
        TCPError, TCPState, TCPTimerServiceHandle,
        socket::{
            SocketInternalHandle, SocketServiceCall, SocketUserHandle, TCPCon, no_socket_found,
        },
    },
    utils::packet::{Packet, TCP},
};

const SOCKET_HANDLE_CHAN_SIZE: usize = 512;

pub trait TransportService {
    type Error;

    fn service_request(
        &mut self,
        call: SocketServiceCall,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

#[derive(Debug)]
pub struct TCPServiceV1 {
    /// sender to dump outgoing IP packets into
    out_svc: ARPServiceHandle,

    socket_table: Slab<SocketInternalHandle>,
    queued_con_req: HashMap<TCPCon, oneshot::Sender<Result<SocketUserHandle, TCPError>>>,

    /// active connections
    con_table: HashMap<TCPCon, usize>,

    /// sockets in LISTEN state
    listen_table: HashMap<SocketAddrV4, usize>,

    port_svc: PortService,
    timer_svc: TCPTimerServiceHandle,
}

impl TransportService for TCPServiceV1 {
    type Error = TCPError;

    #[instrument(skip_all fields(call = %call))]
    async fn service_request(&mut self, call: SocketServiceCall) -> Result<(), TCPError> {
        match call {
            SocketServiceCall::Connect {
                local_addr,
                remote_addr,
                resp,
            } => self.new_connect(local_addr, remote_addr, resp).await,
            SocketServiceCall::Listen { listen_addr, resp } => {
                let handle = self.new_listen(listen_addr).await;
                let key: Option<usize> = if let Ok(ref h) = handle {
                    Some(h.1)
                } else {
                    None
                };

                if let Err(e) = resp.send(handle.map(|h| h.0)) {
                    if let Some(k) = key {
                        self.socket_table.remove(k);
                        self.listen_table.remove(&listen_addr);
                    }
                    error!("couldnt send response for listen socket: {:?}", e);
                };
                Ok(())
            }
            SocketServiceCall::Close { socket_key: _ } => todo!(),

            SocketServiceCall::Segment(packet) => self.service_segment(packet).await,
        }
    }
}

impl TCPServiceV1 {
    pub fn new(out_svc: ARPServiceHandle) -> Self {
        let timer_svc = TCPTimerServiceHandle::init();
        Self {
            out_svc,
            socket_table: Slab::new(),
            queued_con_req: HashMap::new(),
            con_table: HashMap::new(),
            listen_table: HashMap::new(),
            port_svc: PortService::new(),
            timer_svc,
        }
    }

    async fn new_listen(
        &mut self,
        local_addr: SocketAddrV4,
    ) -> Result<(SocketUserHandle, usize), TCPError> {
        self.port_svc.register(local_addr.port())?;

        debug!(%local_addr, "new listening socket");

        let timer_tx = self.timer_svc.register_socket().await;
        let sock = SocketInternalHandle::listen(
            self.out_svc.clone(),
            local_addr,
            SOCKET_HANDLE_CHAN_SIZE,
            timer_tx,
        );
        let key = self.socket_table.vacant_key();
        let user_handler = sock.user_handle(key);

        self.socket_table.insert(sock);
        self.listen_table.insert(local_addr, key);

        Ok((user_handler, key))
    }

    async fn new_connect(
        &mut self,
        local_addr: Ipv4Addr,
        remote_addr: SocketAddrV4,
        resp: oneshot::Sender<Result<SocketUserHandle, TCPError>>,
    ) -> Result<(), TCPError> {
        let port = self.port_svc.request();
        let local_addr = SocketAddrV4::new(local_addr, port);
        let con = TCPCon {
            local_ip: *local_addr.ip(),
            local_port: local_addr.port(),
            remote_ip: *remote_addr.ip(),
            remote_port: remote_addr.port(),
        };

        debug!(%con, "new connecting socket");

        let timer_tx = self.timer_svc.register_socket().await;
        let sock = SocketInternalHandle::connect(
            self.out_svc.clone(),
            local_addr,
            remote_addr,
            SOCKET_HANDLE_CHAN_SIZE,
            timer_tx,
            resp,
        );
        let key = self.socket_table.vacant_key();

        self.socket_table.insert(sock);
        self.con_table.insert(con, key);

        Ok(())
    }
    // OPTIMIZE:
    // we are requesting the status for every submitted packet, no bueno!
    // we should use another MPSC channel such that sockets can inform the service of state changes
    // instead of checking after every segment when the common case is packet exchanges in the
    // ESTABLISHED state
    #[instrument(name = "TCPService", skip_all, fields(con = ?segment.con()))]
    async fn service_segment(&mut self, segment: Packet<TCP>) -> Result<(), TCPError> {
        let seg_con = segment.con();
        let listen_addr = seg_con.local();

        // check for established connection
        if let Some(con_sock) = self
            .con_table
            .get(&seg_con)
            .and_then(|&key| self.socket_table.get(key))
        {
            if con_sock.is_closed() {
                trace!("con socket closed, removing from tables");

                self.con_table.remove(&seg_con);
                self.port_svc.free(seg_con.local_port);
                return Err(TCPError::SocketError(
                    "couldnt deliver segment: connection socket closed".into(),
                ));
            }

            trace!("connection found");
            match con_sock.send_seg(segment).await {
                TCPState::Listen => {
                    trace!("moving con socket back to listen table");
                    let s = self.con_table.remove(&seg_con).expect("we know its there");
                    self.listen_table.insert(listen_addr, s);
                }
                TCPState::Closed => {
                    trace!("con socket closed, removing from tables");
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
            if let Some(resp) = no_socket_found(segment).await {
                warn!("no socket found, sending reset");
                self.out_svc.send(resp.into()).await;
            };
            return Err(TCPError::SocketError("no socket found".into()));
        };

        trace!("listening socket found");
        if listen_sock.is_closed() {
            trace!("listen socket closed, removing from tables");

            self.listen_table.remove(&listen_addr);
            self.port_svc.free(listen_addr.port());
            return Err(TCPError::SocketError(
                "couldnt deliver segment: listen socket closed".into(),
            ));
        }

        match listen_sock.send_seg(segment).await {
            // state didnt change
            TCPState::Listen => {}
            // going from listening to closed should probably not happen
            TCPState::Closed => {
                trace!("listen socket closed, removing from tables");
                self.listen_table.remove(&listen_addr);
                self.port_svc.free(listen_addr.port());
            }
            // move from listening to connection table
            TCPState::SynReceived => {
                trace!("moving listen socket to con table");
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
#[derive(Debug)]
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
