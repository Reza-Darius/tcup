<div align="center">
<img src="images/tcup.png" width="400"/>
</div>

# tcup

Tcup is an asynchronous virtual networking interface capable of handling TCP/IP traffic

## Highlights

- Linux TAP devices to create a virtual interface
- Layer 2 packet switching: Ethernet Frames (RFC 1042) and ARP (RFC 826)
- ICMP echoes (RFC 792)
- Fully asynchronous actor architecture powered by tokio
- Thoughtful memory management: zero copy parsing and buffer reuse for packets
- TCP (RFC 793) and socket API

## Current WIP

- Congestion window and pipelining

## Quick demo

```rust
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpStream},
    str::FromStr,
    time::Duration,
};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // configuring the tap interface
    let if_name = "tcup0";
    let if_addr = "10.0.0.1";
    let subnet = 24;

    // we need a fake host that listens behind our newly created interface
    let virt_host = SocketAddrV4::new(Ipv4Addr::from_str("10.0.0.2").unwrap(), 4000);

    let tcup = tcup::server::init(if_name, (if_addr.parse().unwrap(), subnet), virt_host)
        .await
        .unwrap();

    let mut socket = tcup.listen(virt_host).await.unwrap();
    let data = "hello to TCP! Here is some Data! And Some More!";
    let response = "response from TCUP! Yippie";

    // give some time for the listening socket to setup
    std::thread::sleep(Duration::from_secs(2));

    let handler = std::thread::spawn(move || {
        let mut stream = TcpStream::connect(virt_host).unwrap();

        for slice in data.split_inclusive('!') {
            stream.write_all(slice.as_bytes()).unwrap();
        }

        let mut buf = vec![0; 100];
        let nbyte = stream.read(&mut buf).unwrap();

        assert_eq!(nbyte, response.len());
        println!("sent all bytes");
    });

    // sleep to make sure we get all the data in one swoop since TCP doesnt
    // make any promises about message boundaries
    std::thread::sleep(Duration::from_secs(2));

    let rcv = socket.recv().await.unwrap();

    assert_eq!(&rcv, data.as_bytes());
    println!("got all bytes");

    socket.send(response.as_bytes()).await.unwrap();
    handler.join().unwrap();
}
```
