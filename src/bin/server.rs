use std::{net::Ipv4Addr, str::FromStr};

use tcup::server;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // configuring the tap interface
    let if_name = "tcup0";
    let if_addr = "10.0.0.1";
    let subnet = 24;

    // a fake host that we run our network stack against
    let virt_host = Ipv4Addr::from_str("10.0.0.2").unwrap();

    let server =
        server::tcup::TcupServer::new(if_name, (if_addr.parse().unwrap(), subnet), virt_host)
            .await
            .unwrap();
    server.run().await.unwrap();
}
