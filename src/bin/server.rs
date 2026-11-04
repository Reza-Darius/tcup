use std::{
    io::{Read, Write},
    net::{SocketAddrV4, TcpStream},
    time::Duration,
};

use tokio::time::sleep;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // configuring the tap interface
    let if_name = "tcup0";
    let if_addr = "10.0.0.1";
    let subnet = 24;
    let virt_host: SocketAddrV4 = "10.0.0.2:4000".parse().unwrap();

    let tcup = tcup::server::init(if_name, (if_addr.parse().unwrap(), subnet), virt_host)
        .await
        .unwrap();

    sleep(Duration::from_secs(5)).await;
}
