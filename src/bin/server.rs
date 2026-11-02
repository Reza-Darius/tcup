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

    // we need a fake host that listens behind our newly created interfaace
    let virt_host = SocketAddrV4::new(Ipv4Addr::from_str("10.0.0.2").unwrap(), 4000);

    let tcup = tcup::server::init(if_name, (if_addr.parse().unwrap(), subnet), virt_host)
        .await
        .unwrap();

    let mut socket = tcup.listen(virt_host).await.unwrap();
    let data = vec![2; 1460 * 4];
    let response = vec![1; 1460 * 4];
    let res_len = response.len();

    // give some time for the listening socket to setup
    std::thread::sleep(Duration::from_secs(2));

    let mut stream = TcpStream::connect(virt_host).unwrap();
    stream.write_all(&data).unwrap();

    let handler = std::thread::spawn(move || {
        let mut buf = vec![0; 1460 * 4];
        let mut snd_bytes = 0;

        while snd_bytes < res_len {
            snd_bytes += stream.read(&mut buf).unwrap();
        }

        assert_eq!(snd_bytes, res_len);
        println!("sent all bytes");
    });

    // sleep to make sure we get all the data in one swoop since TCP doesnt make any promise about
    // message boundaries
    std::thread::sleep(Duration::from_secs(2));

    let mut rcv_bytes = 0;
    while rcv_bytes < data.len() {
        let rcv = socket.recv().await.unwrap();
        rcv_bytes += rcv.len();
    }

    assert_eq!(rcv_bytes, data.len());
    println!("got all bytes");

    socket.send(response).await.unwrap();
    handler.join().unwrap();
}
