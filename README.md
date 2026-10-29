<div align="center">
<img src="images/tcup.png" width="400"/>
</div>

# tcup

Tcup is an asynchronous virtual networking interface capable of handling TCP/IP traffic

## Working Features
- uses linux TAP devices to create a virtual interface
- Layer 2 packet switching: Ethernet Frames (RFC 1042) and ARP (RFC 826)
- ICMP echoes (RFC 792)
- TCP Listen (RFC 793)

## Current WIP

- RTO
- Retransmission Queue
- Berkley Socket API

## Quick demo

```rust
use std::{
    io::Write,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream},
    str::FromStr,
    time::Duration,
};


#[tokio::main]
async fn main() {
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
}

```

## Getting Started (coming soon)

build with cargo
```
cargo install tcup
```

run with elevated permissions and run it with an ip and subnet

```
sudo setcap cap_net_admin=ep /usr/bin/tcup
tcup 10.0.0.4/24
```

open a port with your language of choice and enjoy some reliable packets!
