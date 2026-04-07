#![allow(
    dead_code,
    unused_variables,
    unused_assignments,
    non_camel_case_types,
    clippy::upper_case_acronyms
)]

use std::net::Ipv4Addr;

use tcup::{
    error::Result,
    tcup::TCup,
    types::{Mac, MockHost},
};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();

    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let if_name = "tcup";
    let if_addr = "10.0.0.1/24";
    let port = 1337u16;

    let mut dummy_host = MockHost::new(
        Ipv4Addr::new(10, 0, 0, 4),
        Mac::new(0x00, 0x0c, 0x29, 0x6d, 0x50, 0x25),
        port,
    );

    let tcup = TCup::init(if_name, if_addr)?;

    tcup.run(&mut dummy_host).await;

    Ok(())

    // let route = "10.0.0.0/24";
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
