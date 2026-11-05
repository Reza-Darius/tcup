use std::{net::{
    SocketAddr::{self},
    SocketAddrV4, ToSocketAddrs,
}, time::Duration};

use tracing::info;

#[tokio::test]
async fn connect() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .init();

    // configuring the tap interface
    let if_name = "tcup0";
    let if_addr = "10.0.1.1";
    let subnet = 24;
    let virt_host: SocketAddrV4 = "10.0.1.2:4000".parse().unwrap();

    let tcup = tcup::server::init(if_name, (if_addr.parse().unwrap(), subnet), virt_host)
        .await
        .unwrap();

    let handle = tokio::task::spawn(async move {
        let mut remote_addr = None;
        for addr in "example.com:80".to_socket_addrs().unwrap() {
            if let SocketAddr::V4(addr) = addr {
                remote_addr = Some(addr);
            }
        }
        if remote_addr.is_none() {
            panic!("couldnt get a v4 socket addr")
        }
        let mut socket = tcup
            .connect(*virt_host.ip(), remote_addr.unwrap())
            .await
            .unwrap();
        info!("we got a socket");
        let request: Vec<u8> = b"GET / HTTP/1.1\r\n\
                                Host: example.com\r\n\
                                Connection: close\r\n\
                                \r\n"
            .to_vec();
        socket.send(request).await.unwrap();

        let buf = socket.recv().await.unwrap();
        info!("read data:\n {}", std::str::from_utf8(&buf).unwrap());
    });

    tokio::time::sleep(Duration::from_secs(1)).await;
    handle.await.unwrap();
}
