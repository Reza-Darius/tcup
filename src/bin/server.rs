use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpStream},
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

    // we need a fake host that listens behind our newly created interfaace
    let virt_host = SocketAddrV4::new(Ipv4Addr::from_str("10.0.0.2").unwrap(), 4000);

    let tcup = tcup::server::init(if_name, (if_addr.parse().unwrap(), subnet), virt_host)
        .await
        .unwrap();

    let mut socket = tcup.listen(virt_host).await.unwrap();
    let data = "hello to TCP! Here is some Data! And Some More!";

    std::thread::sleep(Duration::from_secs(2));

    let handler = std::thread::spawn(move || {
        let mut stream = TcpStream::connect(virt_host).unwrap();

        for slice in data.split_inclusive('!') {
            info!(slice, "sending data");

            stream.write_all(slice.as_bytes()).unwrap();
        }

        let mut buf = vec![0; 100];
        let nbyte = stream.read(&mut buf).unwrap();

        info!("read {} bytes", nbyte);
    });

    std::thread::sleep(Duration::from_secs(2));

    let rcv = socket.recv().await.unwrap();

    assert_eq!(&rcv, data.as_bytes());
    info!("got all bytes!");

    socket.send("response from TCUP! Yippie").await.unwrap();
    std::thread::sleep(Duration::from_secs(2));
    handler.join().unwrap();
}
