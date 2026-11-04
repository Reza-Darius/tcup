use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use slab::Slab;
use tokio::sync::{
    mpsc::{Receiver, Sender, channel},
    oneshot,
};
use tracing::{debug, trace};

use crate::tcp::heap::MinHeap;

/// After sending the final FIN+ACK, you must linger before fully closing the socket. Prevents old duplicate segments from a dead connection being mistaken for a new one.
pub const TIME_WAIT: Duration = MSL.saturating_mul(2);

/// Maximum segment lifetime
pub const MSL: Duration = Duration::from_secs(60);
pub const CONNECTION_LIFETIME_LIMIT: Duration = Duration::from_secs(100);

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

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, Hash)]
pub enum TimerKind {
    RTO,
    TimeWait,
}

const N_TIMER: usize = 2;

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
    async fn run(mut self) {
        debug!("starting TCP timer service");

        let mut int = tokio::time::interval(Duration::from_millis(CLOCK_GRANULARITY));
        int.tick().await;
        loop {
            tokio::select! {biased;
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
                trace!(socket_key, ?kind, "set timer");
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
        assert!(!of, "an overflow would make judging a timer ambiguous");
        *entry = generation;
        generation
    }

    fn remove_socket(&mut self, socket_key: usize) {
        self.sockets.remove(socket_key);
        self.timer.retain(|(key, _), _| socket_key != *key);
    }

    fn register_socket(&mut self) -> TCPTimerCBHandle {
        let (tx, rx) = channel(SOCKET_CHAN_BUF_SIZE);
        let key = self.sockets.insert(SocketEntry {
            sender: tx,
            generations: [0; _],
        });

        TCPTimerCBHandle {
            sender: TCPTimerServiceHandle {
                sender: self.snd.clone(),
            },
            receiver: rx,
            socket_key: key,
        }
    }

    async fn handle_tick(&mut self) {
        let Some(first) = self.deadlines.peek().copied() else {
            return;
        };
        // is the time up?
        if first.deadline > Instant::now() {
            return;
        }

        self.deadlines.pop();

        // is the entry stale?
        let reg_gen = self.timer[&(first.socket_key, first.kind)].generation;
        let Some(socket_entry) = self.sockets.get(first.socket_key) else {
            // timer for non existing socket found
            return;
        };
        if socket_entry.generations[first.kind as usize] > reg_gen {
            return;
        }

        trace!(?first.kind, "sending timer notif");
        if let Err(e) = socket_entry.sender.send(first.kind).await {
            debug!("couldnt send timer notif to socket");
            self.sockets.remove(first.socket_key);
        }
    }
}

/// handle for transport service
#[derive(Debug, Clone)]
pub struct TCPTimerServiceHandle {
    sender: Sender<TCPTimerMessage>,
}

impl TCPTimerServiceHandle {
    /// starts the timer service worker
    #[must_use]
    pub fn init() -> Self {
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
        TCPTimerServiceHandle { sender: tx }
    }

    pub async fn register_socket(&self) -> TCPTimerCBHandle {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(TCPTimerMessage::RegisterSocket { resp: tx })
            .await
            .unwrap();

        rx.await.unwrap()
    }
}

/// handle for individual TCP worker
#[derive(Debug)]
pub struct TCPTimerCBHandle {
    sender: TCPTimerServiceHandle,
    receiver: Receiver<TimerKind>,
    socket_key: usize,
}

impl TCPTimerCBHandle {
    pub async fn recv(&mut self) -> TimerKind {
        self.receiver
            .recv()
            .await
            .expect("the receiver cant be closed")
    }

    pub async fn set_timer(&self, kind: TimerKind, deadline: Instant) {
        self.sender
            .sender
            .send(TCPTimerMessage::SetTimer {
                socket_key: self.socket_key,
                kind,
                deadline,
            })
            .await
            .expect("if this send fails the timer worker is down which is BIG trouble");
    }
    pub async fn remove_timer(&self, kind: TimerKind) {
        self.sender
            .sender
            .send(TCPTimerMessage::RemoveTimer {
                socket_key: self.socket_key,
                kind,
            })
            .await
            .expect("if this send fails the timer worker is down which is BIG trouble");
    }
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
        resp: oneshot::Sender<TCPTimerCBHandle>,
    },
    RemoveSocket {
        socket_key: usize,
    },
}
