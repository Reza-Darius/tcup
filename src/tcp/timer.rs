use std::{sync::atomic::AtomicU64, time::Duration};

pub static TICK: AtomicU64 = AtomicU64::new(0);

/// Retransmission timeout, how long to wait for an ACK before resending the segment in seconds
///
/// double on each retry
pub const RTO_START: u64 = 1;
pub const RTO_CAP: u64 = 60;

/// After sending the final FIN+ACK, you must linger before fully closing the socket. Prevents old duplicate segments from a dead connection being mistaken for a new one.
pub const TW: u64 = MSL * 2;

/// Maximum segment lifetime
pub const MSL: u64 = 60;
pub const FIN_TIMEOUT: u64 = 60;

pub fn start_clock() {
    tokio::spawn(async {
        let mut int = tokio::time::interval(Duration::from_millis(500));
        loop {
            int.tick().await;
            TICK.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    });
}
