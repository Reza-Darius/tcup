use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use slab::Slab;
use tokio::sync::{
    mpsc::{Receiver, Sender, channel},
    oneshot,
};
use tracing::debug;

use crate::tcp::heap::MinHeap;

/// After sending the final FIN+ACK, you must linger before fully closing the socket. Prevents old duplicate segments from a dead connection being mistaken for a new one.
pub const TIME_WAIT: u64 = MSL;

/// Maximum segment lifetime
pub const MSL: u64 = 60; // seconds
pub const FIN_TIMEOUT: u64 = 60; // seconds

pub const CLOCK_GRANULARITY: u64 = 10; // miliseconds
const SOCKET_CHAN_BUF_SIZE: usize = 1024;
const TIMER_HEAP_MAX_SIZE: usize = 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Timer {
    deadline: Instant,
    socket_key: usize,
    kind: TimerKind,
}

impl Ord for Timer {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.deadline.cmp(&other.deadline)
    }
}

impl PartialOrd for Timer {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Hash)]
pub enum TimerKind {
    RTO,
}

const N_TIMER: usize = 1;

struct SocketEntry {
    sender: Sender<TimerKind>,
    generations: [u32; N_TIMER], // current gen
}

struct TimerEntry {
    generation: u32,
}

struct TCPTimer {
    sockets: Slab<SocketEntry>,
    // keyed by socket_key and timer type
    timer: HashMap<(usize, TimerKind), TimerEntry>,

    deadlines: MinHeap<Timer>,

    rcv: Receiver<TCPTimerMessage>,
    snd: Sender<TCPTimerMessage>,
}

impl TCPTimer {
    pub fn init() -> Sender<TCPTimerMessage> {
        let (tx, rx) = channel(SOCKET_CHAN_BUF_SIZE);
        let tx_cl = tx.clone();

        let timer = TCPTimer {
            sockets: Slab::new(),
            timer: HashMap::new(),
            deadlines: MinHeap::new(TIMER_HEAP_MAX_SIZE),
            rcv: rx,
            snd: tx_cl,
        };

        tokio::spawn(async move { timer.run().await });
        tx
    }

    async fn run(mut self) {
        let mut int = tokio::time::interval(Duration::from_millis(CLOCK_GRANULARITY));
        int.tick().await;
        loop {
            tokio::select! {
                msg = self.rcv.recv() => {
                    if let Some(msg) = msg {
                        self.handle_msg(msg);
                    } else {
                        break
                    }
                }
                _ = int.tick() => {
                    self.handle_tick().await;
                }
            }
        }

        debug!("shutting down TCP timer service");
    }

    fn handle_msg(&mut self, msg: TCPTimerMessage) {
        match msg {
            TCPTimerMessage::SetTimer {
                socket_key,
                kind,
                deadline,
            } => {
                // update generation
                let generation = self.update_generation(socket_key, kind);

                // overwrite entry in timer table
                self.timer
                    .insert((socket_key, kind), TimerEntry { generation });

                // insert into heap
                self.deadlines.insert(Timer {
                    deadline,
                    socket_key,
                    kind,
                });
            }
            TCPTimerMessage::RemoveTimer { socket_key, kind } => {
                // we just bump up the generation count
                self.update_generation(socket_key, kind);
            }
            TCPTimerMessage::RegisterSocket { resp } => {
                let handler = self.register_socket();
                resp.send(handler);
            }
            TCPTimerMessage::RemoveSocket { socket_key } => {
                self.remove_socket(socket_key);
            }
        }
    }

    fn update_generation(&mut self, socket_key: usize, kind: TimerKind) -> u32 {
        let entry = &mut self.sockets[socket_key].generations[kind as usize];
        let (generation, of) = entry.overflowing_add(1);
        assert!(!of, "uhh overflow kinda breaks all this");
        *entry = generation;
        generation
    }

    fn remove_socket(&mut self, socket_key: usize) {
        self.sockets.remove(socket_key);
        self.timer.retain(|(key, _), _| socket_key != *key);
    }

    fn register_socket(&mut self) -> TCPTimerCBHandler {
        let (tx, rx) = channel(SOCKET_CHAN_BUF_SIZE);
        let key = self.sockets.insert(SocketEntry {
            sender: tx,
            generations: [0; _],
        });

        TCPTimerCBHandler {
            sender: TCPTimerHandler {
                sender: self.snd.clone(),
            },
            receiver: rx,
            socket_key: key,
        }
    }

    async fn handle_tick(&mut self) {
        let now = Instant::now();
        if let Some(first) = self.deadlines.peek().copied() {
            // is the time up?
            if first.deadline > now {
                return;
            }


            // is the entry stale?
            let reg_gen = self.timer[&(first.socket_key, first.kind)].generation;
            let socket_entry = &self.sockets[first.socket_key];
            if socket_entry.generations[first.kind as usize] > reg_gen {
                return;
            }

            // TODO: on error, remove the socket
            socket_entry.sender.send(first.kind).await;
            self.deadlines.pop();
        }
    }
}

/// handle for transport service
#[derive(Clone)]
pub struct TCPTimerHandler {
    sender: Sender<TCPTimerMessage>,
}

impl TCPTimerHandler {
    pub fn register_socket(&self) {}
}

/// handle for individual TCP worker
pub struct TCPTimerCBHandler {
    sender: TCPTimerHandler,
    receiver: Receiver<TimerKind>,
    socket_key: usize,
}

pub enum TCPTimerMessage {
    SetTimer {
        socket_key: usize,
        kind: TimerKind,
        deadline: Instant,
    },
    RemoveTimer {
        socket_key: usize,
        kind: TimerKind,
    },
    RegisterSocket {
        resp: oneshot::Sender<TCPTimerCBHandler>,
    },
    RemoveSocket {
        socket_key: usize,
    },
}
