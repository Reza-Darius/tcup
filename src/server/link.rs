use std::net::IpAddr;

use crate::{
    eth::Mac,
    tap::device::{
        TAPDevice, TAPDeviceOptions, TAPStream,
        TapError::{self},
    },
    utils::packet::{ETH, Packet},
};

use futures::StreamExt;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tracing::{error, instrument};

pub trait LinkService {
    type Sender: LinkSink + Clone;

    fn sender(&self) -> Self::Sender;
    fn recv(&mut self) -> Option<Packet<ETH>>;

    fn addr(&self) -> IpAddr;
    fn mac(&self) -> Mac;
}

pub trait LinkSink {
    type Error;
    async fn send_frame(&self, packet: Packet<ETH>) -> Result<(), Self::Error>;
    async fn send_frames(&self, packets: Vec<Packet<ETH>>) -> Result<(), Self::Error>;
}

pub enum TAPActorMessage {
    Packet(Packet<ETH>),
    Packets(Vec<Packet<ETH>>),
}

impl From<Packet<ETH>> for TAPActorMessage {
    fn from(value: Packet<ETH>) -> Self {
        TAPActorMessage::Packet(value)
    }
}

impl From<Vec<Packet<ETH>>> for TAPActorMessage {
    fn from(value: Vec<Packet<ETH>>) -> Self {
        TAPActorMessage::Packets(value)
    }
}

pub struct TAPActorHandle {
    pub addr: Option<IpAddr>,
    pub mac: Mac,
    sender: Sender<TAPActorMessage>,
    receiver: Receiver<Packet<ETH>>,
}

impl TAPActorHandle {
    /// initializes a new TAP device, panics if called more than once
    pub async fn new(
        name: impl Into<String>,
        opts: TAPDeviceOptions,
        buf_size: usize,
    ) -> Result<Self, TapError> {
        let tap = TAPDevice::new(name, opts).await?;
        let addr = tap.addr();
        let mac = tap.mac();
        let (msg_tx, msg_rx) = channel::<TAPActorMessage>(buf_size);
        let (packet_tx, packet_rx) = channel::<Packet<ETH>>(buf_size);

        let mut actor = TAPActor {
            tap: tap.into_stream(),
            receiver: msg_rx,
            sender: packet_tx,
        };

        tokio::spawn(async move { actor.run().await });

        Ok(TAPActorHandle {
            addr,
            mac,
            sender: msg_tx,
            receiver: packet_rx,
        })
    }

    pub fn sender(&self) -> Sender<TAPActorMessage> {
        self.sender.clone()
    }

    pub async fn recv(&mut self) -> Option<Packet<ETH>> {
        self.receiver.recv().await
    }
}

impl TAPActorHandle {
    pub async fn send(&self, msg: TAPActorMessage) {
        self.sender.send(msg).await.unwrap();
    }
}

pub struct TAPReceiver(Receiver<Packet<ETH>>);

impl TAPReceiver {
    pub async fn recv(&mut self) -> Packet<ETH> {
        self.0.recv().await.unwrap()
    }
}

pub struct TAPActor {
    tap: TAPStream,
    receiver: Receiver<TAPActorMessage>,
    sender: Sender<Packet<ETH>>,
}

impl TAPActor {
    #[instrument(name = "TAP_actor", skip_all)]
    async fn run(&mut self) {
        loop {
            tokio::select! {
                Some(res) = self.tap.next() => {
                    match res {
                        Err(e) if e.kind() != std::io::ErrorKind::InvalidData => {
                            error!(%e, "error when reading from stream");
                        },
                        Ok(packet) => {
                            self.sender.send(packet).await.expect("the receiver cant be closed");
                        },
                        _ => {}
                    };
                }
                Some(msg) = self.receiver.recv() => {
                    if let Err(e) = self.handle_message(msg).await {
                        error!(%e, "error when handling message");
                    };
                }
            }
        }
    }

    async fn handle_message(&mut self, msg: TAPActorMessage) -> Result<(), TapError> {
        match msg {
            TAPActorMessage::Packet(packet) => self.tap.send_frame(&packet).await,
            TAPActorMessage::Packets(packets) => self.tap.send_frames(&packets).await,
        }
    }
}
