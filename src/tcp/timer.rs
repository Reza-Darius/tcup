use std::{sync::atomic::AtomicU64, time::Duration};

pub static TICK: AtomicU64 = AtomicU64::new(0);

/// After sending the final FIN+ACK, you must linger before fully closing the socket. Prevents old duplicate segments from a dead connection being mistaken for a new one.
pub const TIME_WAIT: u64 = MSL * 1;

/// Maximum segment lifetime
pub const MSL: u64 = 60; // seconds
pub const FIN_TIMEOUT: u64 = 60; // seconds

/// granularity of the clock, the linux kernel uses 200ms and 500ms
pub const CLOCK_GRAN: u64 = 100; // miliseconds

pub fn start_clock() {
    tokio::spawn(async {
        let mut int = tokio::time::interval(Duration::from_millis(CLOCK_GRAN));
        loop {
            int.tick().await;
            TICK.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    });
}
