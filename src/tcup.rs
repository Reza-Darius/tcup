use std::str::FromStr;
use std::sync::Arc;
use std::{collections::HashMap, net::Ipv4Addr};

use crate::error::Result;
use crate::eth::{ETH_FRAME_MAX_SIZE, EthFrame, handle_frame};
use crate::tap::TAPDevice;
use crate::tcp::sock::Socket;
use crate::tcp::timer::start_clock;
use crate::types::{MockHost, TCPCon};
use crate::utils::setup_cap;
use parking_lot::RwLock;
use tracing::{error, trace, warn};

/// cheaply clonable singleton
#[derive(Debug, Clone)]
pub struct TCup {
    inner: Arc<TCupInner>,
}

#[derive(Debug)]
struct TCupInner {
    ip: Ipv4Addr,
    subnet: u8,
    tap: TAPDevice,
    con_table: RwLock<HashMap<TCPCon, Socket>>,
}

impl TCup {
    pub fn init(name: &str, addr: &str) -> Result<Self> {
        setup_cap()?;

        let tap = TAPDevice::new(name)?;
        tap.set_if_link()?;
        tap.set_if_addr(addr)?;

        let mut parts = addr.split('/');

        let inner = TCupInner {
            ip: Ipv4Addr::from_str(parts.next().unwrap())?,
            subnet: str::parse::<u8>(parts.next().unwrap()).unwrap(),
            tap,
            con_table: RwLock::new(HashMap::new()),
        };

        Ok(TCup {
            inner: Arc::new(inner),
        })
    }

    /// retrieves the socket handle for a connection
    pub fn get_sock(&self, con: &TCPCon) -> Option<Socket> {
        self.inner.con_table.read().get(con).cloned()
    }

    /// inserts a new socket handle into the connection table
    pub fn insert_sock(&self, con: &TCPCon, socket: Socket) {
        if self.inner.con_table.write().insert(*con, socket).is_some() {
            warn!("overwriting socket in con table");
        };
    }

    pub fn remove_sock(&self, con: &TCPCon) {
        if self.inner.con_table.write().remove(con).is_none() {
            warn!("removing a socket that didnt exist from con table");
        };
    }

    /// starts the main event loop
    pub async fn run(self, host: &mut MockHost) -> ! {
        let mut buf = Box::new([0u8; ETH_FRAME_MAX_SIZE]);

        start_clock();

        println!("listening on {}", self.inner.ip);

        loop {
            let tcup = self.clone();
            let n = tcup.read_tap(&mut *buf).await.unwrap();
            trace!("{n} bytes received");

            let frame = match EthFrame::from_be_bytes(&buf[..n]) {
                Ok(f) => f,
                Err(e) => {
                    error!(%e, "failed to create frame");
                    continue;
                }
            };
            trace!("frame received");

            if let Err(e) = handle_frame(frame, tcup, &mut *host).await {
                error!("dispatch error: {e}");
            }
        }
    }

    /// reads from the TAP device
    pub async fn read_tap(&self, buf: &mut [u8]) -> Result<usize> {
        self.inner.tap.read(buf).await
    }

    /// writes to the TAP device
    pub async fn write_tap(&self, frame: EthFrame) -> Result<usize> {
        self.inner.tap.write(frame).await
    }

    // pub fn get_socket(&self, con_k: &ConnectionKey) -> Option<&Socket> {
    //     self.con_table.read().table.get(con_k)
    // }
}
