use std::{
    io::{Read, Write},
    net::{SocketAddrV4, TcpStream},
    time::Duration,
};

use tokio::time::sleep;

#[tokio::test]
async fn send_receive() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .init();

    // configuring the tap interface
    let if_name = "tcup0";
    let if_addr = "10.0.0.1";
    let subnet = 24;
    let virt_host: SocketAddrV4 = "10.0.0.2:4000".parse().unwrap();

    let tcup = tcup::server::init(if_name, (if_addr.parse().unwrap(), subnet), virt_host)
        .await
        .unwrap();

    let mut socket = tcup.listen(virt_host).await.unwrap();
    let data = vec![2; 1460 * 4];
    let data_len = data.len();
    let response = vec![1; 1460 * 4];
    let res_len = response.len();

    // give some time for the listening socket to setup
    sleep(Duration::from_secs(1)).await;

    let handler = tokio::task::spawn_blocking(move || {
        let mut stream = TcpStream::connect(virt_host).unwrap();
        stream.write_all(&data).unwrap();

        let mut buf = vec![0; 1460 * 4];
        let mut snd_bytes = 0;

        while snd_bytes < res_len {
            snd_bytes += stream.read(&mut buf).unwrap();
        }

        assert_eq!(snd_bytes, res_len);
    });

    // sleep to make sure we get all the data in one swoop since TCP doesnt make any promise about
    // message boundaries
    sleep(Duration::from_secs(1)).await;

    let mut rcv_bytes = 0;
    while rcv_bytes < data_len {
        let rcv = socket.recv().await.unwrap();
        rcv_bytes += rcv.len();
    }

    assert_eq!(rcv_bytes, data_len);

    socket.send(response).await.unwrap();
    handler.await.unwrap();
    sleep(Duration::from_secs(1)).await;
}
