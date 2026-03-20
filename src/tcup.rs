use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;
use std::{collections::HashMap, net::Ipv4Addr};

use crate::error::Result;
use crate::eth::{ETH_FRAME_MAX_SIZE, EthFrame, handle_frame};
use crate::tap::TAPDevice;
use crate::types::{MockHost, Socket, TCPCon};
use crate::utils::setup_cap;
use parking_lot::RwLock;
use tracing::{error, info};

pub static CLOCK: AtomicU64 = AtomicU64::new(0);
pub const INTERVAL: u64 = 4;

#[derive(Debug)]
pub struct TCup {
    pub ip: Ipv4Addr,
    pub sub: u8, // subnet mask
    pub tap: TAPDevice,
    pub con_table: RwLock<HashMap<TCPCon, Socket>>,
}

impl TCup {
    pub fn init(name: &str, addr: &str) -> Result<Self> {
        setup_cap()?;

        let tap = TAPDevice::new(name)?;
        tap.set_if_link()?;
        tap.set_if_addr(addr)?;

        let mut parts = addr.split('/');

        let tcup = TCup {
            ip: Ipv4Addr::from_str(parts.next().unwrap())?,
            sub: str::parse::<u8>(parts.next().unwrap()).unwrap(),
            tap,
            con_table: RwLock::new(HashMap::new()),
        };

        Ok(tcup)
    }

    /// starts the main event loop
    pub async fn listen(self, host: &mut MockHost) {
        let mut buf = Box::new([0u8; ETH_FRAME_MAX_SIZE]);
        let tcup = Arc::new(self);

        tokio::spawn(drive_clock());

        loop {
            println!("listening...");

            let n = tcup.read_tap(&mut *buf).await.unwrap();
            info!("{n} bytes received");

            let frame = match EthFrame::new(&buf[..n]) {
                Ok(f) => f,
                Err(e) => {
                    error!("failed to create frame");
                    continue;
                }
            };

            if let Err(e) = handle_frame(frame, tcup.clone(), &mut *host).await {
                error!("dispatch error: {e}");
            }
        }
    }

    /// reads from the TAP device
    pub async fn read_tap(&self, buf: &mut [u8]) -> Result<usize> {
        self.tap.read(buf).await
    }

    /// writes to the TAP device
    pub async fn write_tap(&self, frame: EthFrame) -> Result<usize> {
        self.tap.write(frame).await
    }

    // pub fn get_socket(&self, con_k: &ConnectionKey) -> Option<&Socket> {
    //     self.con_table.read().table.get(con_k)
    // }
}

async fn drive_clock() {
    let mut int = tokio::time::interval(Duration::new(INTERVAL, 0));
    loop {
        int.tick().await;
        CLOCK.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
