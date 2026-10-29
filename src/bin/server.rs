use std::{
    io::Write,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream},
    str::FromStr,
    time::Duration,
};

use tracing::info;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    // configuring the tap interface
    let if_name = "tcup0";
    let if_addr = "10.0.0.1";
    let subnet = 24;

    // a fake host listening
    let virt_host = SocketAddrV4::new(Ipv4Addr::from_str("10.0.0.2").unwrap(), 4000);

    let tcup = tcup::server::init(if_name, (if_addr.parse().unwrap(), subnet), virt_host)
        .await
        .unwrap();

    std::thread::sleep(Duration::from_secs(2));

    let mut stream = TcpStream::connect(virt_host).unwrap();
    let data = "hello to TCP! Here is some Data! And Some More!";

    for slice in data.split_inclusive('!') {
        info!("sending data");

        stream.write_all(slice.as_bytes()).unwrap();
    }

    let SocketAddr::V4(addr) = stream.local_addr().unwrap() else {
        panic!()
    };

    std::thread::sleep(Duration::from_secs(2));

    let rcv = tcup
        .request_data(virt_host, addr)
        .await
        .unwrap()
        .await
        .unwrap();

    assert_eq!(&rcv, data.as_bytes());
    info!("got all bytes!");
}
