use std::str::FromStr;
use std::sync::Arc;
use std::{collections::HashMap, net::Ipv4Addr};

use crate::error::Result;
use crate::eth::{ETH_FRAME_MAX_SIZE, EthFrame, handle_frame};
use crate::tap::TAPDevice;
use crate::types::{MockHost, Socket, TCPCon};
use crate::utils::setup_cap;
use parking_lot::RwLock;
use tracing::{error, info};

#[derive(Debug)]
pub struct TCup {
    pub ip: Ipv4Addr,
    pub tap: TAPDevice,
    pub con_table: RwLock<HashMap<TCPCon, Socket>>,
}

impl TCup {
    pub fn init(name: &str, addr: &str) -> Result<Self> {
        setup_cap()?;

        let tap = TAPDevice::new(name)?;
        tap.set_if_link()?;
        tap.set_if_addr(addr)?;

        let tcup = TCup {
            ip: Ipv4Addr::from_str(addr)?,
            tap,
            con_table: RwLock::new(HashMap::new()),
        };

        Ok(tcup)
    }

    /// starts the main event loop
    pub async fn listen(self, host: &mut MockHost) {
        let mut buf = Box::new([0u8; ETH_FRAME_MAX_SIZE]);
        let tcup = Arc::new(self);

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
