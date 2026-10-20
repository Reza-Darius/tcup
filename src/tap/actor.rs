#![allow(dead_code, unused_variables, unused_assignments)]

use crate::{
    tap::common::{
        TAPDevice, TAPDeviceOptions, TAPStream,
        TapError::{self},
    },
    utils::packet::{ETH, Packet},
};

use futures::StreamExt;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tracing::error;

pub async fn tap_init(
    name: impl Into<String>,
    opts: TAPDeviceOptions,
    buf_size: usize,
) -> Result<(TAPHandler, TAPReceiver), TapError> {
    let tap = TAPDevice::new(name, opts).await?;
    let (msg_tx, msg_rx) = channel::<TAPActorMessage>(buf_size);
    let (packet_tx, packet_rx) = channel::<Packet<ETH>>(buf_size);

    let mut actor = TAPActor {
        tap: tap.into_stream(),
        receiver: msg_rx,
        sender: packet_tx,
    };

    tokio::spawn(async move { actor.run().await });

    Ok((TAPHandler(msg_tx), TAPReceiver(packet_rx)))
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

#[derive(Clone)]
pub struct TAPHandler(Sender<TAPActorMessage>);

impl TAPHandler {
    pub async fn send(&self, msg: TAPActorMessage) {
        self.0.send(msg).await.unwrap();
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
    async fn run(&mut self) {
        loop {
            tokio::select! {
                Some(res) = self.tap.next() => {
                    match res {
                        Err(e) => {
                            error!(%e, "error when reading from stream");
                        },
                        Ok(packet) => {
                            self.sender.send(packet).await.expect("the receiver cant be closed");
                        },
                    };
                }
                Some(msg) = self.receiver.recv() => {
                    let _ =self.handle_message(msg).await;
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
