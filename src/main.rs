#![allow(dead_code, unused_variables, unused_assignments, non_camel_case_types)]

use std::{net::Ipv4Addr, sync::Arc};

use parking_lot::RwLock;
use tracing::{error, info};

use crate::{
    error::Result,
    eth::{ETH_FRAME_MAX_SIZE, EthFrame, handle_frame},
    tap::TAPDevice,
    types::{MAC, MockHost, TCup},
    utils::setup_cap,
};

mod arp;
mod error;
mod eth;
mod icmp;
mod ip;
mod tap;
mod tcp;
mod types;
mod utils;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();

    // TODO: take command line arguments or env variables

    let name = "tap0";
    let addr = "10.0.0.1/24";
    let route = "10.0.0.0/24";

    let mut dummy_host = MockHost::new(
        Ipv4Addr::new(10, 0, 0, 4),
        MAC::new(0x00, 0x0c, 0x29, 0x6d, 0x50, 0x25),
    );

    let tcup = Arc::new(TCup::init(name, addr)?);

    listen(tcup, &mut dummy_host).await;

    Ok(())

    // let tap = TAPDevice::new(name)?;
    // tap.set_if_link()?;
    // tap.set_if_addr(addr)?;
    // // tap.set_if_route(route)?;

    // let mut buf = Box::new([0u8; ETH_FRAME_MAX_SIZE]);

    // loop {
    //     println!("listening...");

    //     let n = tap.read(&mut *buf).await.unwrap();
    //     info!("{n} bytes received");

    //     let frame = EthFrame::new(&buf[..n])?;

    //     let _ = handle_frame(frame, &tap, &mut dummy_host);
    // }
}

/// starts the main event loop
async fn listen(tcup: Arc<TCup>, host: &mut MockHost) {
    let mut buf = Box::new([0u8; ETH_FRAME_MAX_SIZE]);

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
