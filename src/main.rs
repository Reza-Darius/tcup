#![allow(dead_code, unused_variables, unused_assignments)]

use std::net::Ipv4Addr;

use tracing::info;

use crate::{
    error::Result,
    eth::{ETH_FRAME_MAX_SIZE, EthFrame, handle_frame},
    tap::TAPDevice,
    types::{MAC, MockHost},
    utils::setup_cap,
};

mod arp;
mod error;
mod eth;
mod ip;
mod tap;
mod types;
mod utils;

fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();

    let name = "tap0";
    let addr = "10.0.0.1/24";
    let route = "10.0.0.0/24";

    setup_cap()?;

    let tap = TAPDevice::new(name)?;
    tap.set_if_link()?;
    tap.set_if_addr(addr)?;
    // tap.set_if_route(route)?;

    let mut dummy_host = MockHost::new(
        Ipv4Addr::new(10, 0, 0, 4),
        MAC::new(0x00, 0x0c, 0x29, 0x6d, 0x50, 0x25),
    );

    let mut buf = Box::new([0u8; ETH_FRAME_MAX_SIZE]);

    loop {
        println!("listening...");

        let n = tap.read(&mut *buf).unwrap();
        info!("{n} bytes received");

        let frame = EthFrame::from_bytes(&buf[..n])?;

        if let Err(e) = handle_frame(frame, &tap, &mut dummy_host) {
            println!("{e}");
        };
    }
}
