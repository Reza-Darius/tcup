use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::{collections::HashMap, net::Ipv4Addr};

use crate::Error;
use crate::arp::arp_broadcast;
use crate::error::Result;
use crate::eth::{ETH_FRAME_MAX_SIZE, EthFrame, handle_frame};
use crate::tap::TAPDevice;
use crate::tcp::sock::Socket;
use crate::tcp::timer::start_clock;
use crate::types::{Mac, TCPCon};
use crate::utils::{get_default_gateway, setup_cap};
use parking_lot::{Mutex, RwLock};
use tokio::sync::Notify;
use tracing::{debug, error, info, trace, warn};

/// cheaply clonable singleton
#[derive(Debug, Clone)]
pub struct TCup {
    inner: Arc<TCupInner>,
}

#[derive(Debug)]
struct TCupInner {
    ip: Ipv4Addr,
    mac: Mac,
    subnet: u8,
    gateway: Ipv4Addr,
    tap: TAPDevice,

    con_table: RwLock<HashMap<TCPCon, Socket>>,
    arp_table: Mutex<HashMap<Ipv4Addr, Mac>>,

    arp_chiller: Mutex<HashMap<Ipv4Addr, Arc<Notify>>>,
    // SocketId, Socket table
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
            mac: tap.get_mac()?,
            subnet: str::parse::<u8>(parts.next().unwrap()).unwrap(),
            gateway: get_default_gateway().unwrap(),
            tap,
            con_table: RwLock::new(HashMap::new()),
            arp_table: Mutex::new(HashMap::new()),
            arp_chiller: Mutex::new(HashMap::new()),
        };

        Ok(TCup {
            inner: Arc::new(inner),
        })
    }

    /// get the ipv4 address of the TAP interface
    pub fn addr(&self) -> Ipv4Addr {
        self.inner.ip
    }

    /// get the hardware address of the TAP interface
    pub fn mac(&self) -> Mac {
        self.inner.mac
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
    pub async fn run(self) {
        let mut buf = Box::new([0u8; ETH_FRAME_MAX_SIZE]);

        start_clock();

        info!("listening on {}", self.inner.ip);

        // TODO: graceful shutdown

        loop {
            let tcup = self.clone();

            tokio::select! {
                res = tcup.inner.tap.read(&mut *buf) => {
                    match res {
                        Err(e) => error!(%e, "error when reading from tap"),
                        Ok(n) => {
                            // TODO find out the true ethernet frame min size
                            if n < 15 {
                                error!("less than one frame worth of bytes received");
                                continue;
                            }

                            trace!("{n} bytes received");

                            handle_tap(tcup, buf.as_mut()).await;
                        }
                    }
                }
                _ = shutdown() => {}
                // read_ctrl_bus() => {}
                // read_data_bus() => {}
            }
        }
    }

    /// writes to the TAP device
    pub async fn write_tap(&self, frame: EthFrame) -> Result<usize> {
        self.inner.tap.write(frame).await
    }

    pub fn arp_table_insert(&self, ip: Ipv4Addr, mac: Mac) -> Option<Mac> {
        debug!(%ip, %mac, "inserting into ARP table");

        let mut arp_lock = self.inner.arp_table.lock();
        let res = arp_lock.insert(ip, mac);

        let mut chill_guard = self.inner.arp_chiller.lock();
        if let Some(notify) = chill_guard.get(&ip) {
            notify.notify_waiters();
            chill_guard.remove(&ip);
        };
        res
    }

    pub fn arp_table_get(&self, ip: Ipv4Addr) -> Option<Mac> {
        self.inner.arp_table.lock().get(&ip).cloned()
    }

    pub async fn resolve_with_arp(&self, dest_ip: Ipv4Addr) -> Result<Mac> {
        if let Some(mac) = self.arp_table_get(dest_ip) {
            return Ok(mac);
        }

        let mask = cidr_to_mask(self.inner.subnet);
        let ip = if dest_ip.to_bits() & mask == self.inner.ip.to_bits() & mask {
            dest_ip
        } else {
            trace!("getting gateway");
            self.inner.gateway
        };

        let mut inserted = false;

        // we need to do this because drop(guard) doesnt work due to NLL bugs
        let notify = self
            .inner
            .arp_chiller
            .lock()
            .entry(ip)
            .or_insert_with(|| {
                inserted = true;
                Arc::new(Notify::new())
            })
            .clone();

        if !inserted {
            // in this branch someone is already waiting for the arp to get resolved
            // so we try to piggyback off of it
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(5)) => {
                      Err(Error::Arp("ARP failed: host unreachable".to_string()))
                }
                _ = notify.notified() => {
                      Ok(self.arp_table_get(ip).expect("we know its there"))

                }
            }
        } else {
            debug!(%ip, "issuing ARP request");

            let mut tries = 0;

            while tries < 5 {
                arp_broadcast(self, ip).await?;
                tries += 1;

                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {
                        continue;
                    }
                    _ = notify.notified() => {
                        return Ok(self.arp_table_get(ip).expect("we know its there"))
                    }

                }
            }
            Err(Error::Arp("ARP failed: host unreachable".to_string()))
        }
    }

    // pub fn get_socket(&self, con_k: &ConnectionKey) -> Option<&Socket> {
    //     self.con_table.read().table.get(con_k)
    // }
}

/// reads from the TAP device
async fn handle_tap(tcup: TCup, mut buf: impl AsMut<[u8]>) {
    let buf = buf.as_mut();
    let n = buf.len();

    let frame = match EthFrame::from_be_bytes(&buf[..n]) {
        Ok(f) => f,
        Err(e) => {
            error!(%e, "failed to create frame");
            return;
        }
    };

    trace!("frame received");

    if let Err(e) = handle_frame(frame, tcup).await {
        error!("dispatch error: {e}");
    }
}

async fn shutdown() {
    tokio::signal::ctrl_c().await.expect("ctrl c signal error");
}
