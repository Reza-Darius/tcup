use std::cmp::{max, min};
use std::time::{Duration, Instant};

use tracing::trace;

use crate::tcp::timer::CLOCK_GRANULARITY;

const MIN: Duration = Duration::from_secs(1);
const MAX: Duration = Duration::from_mins(1);

/// RFC 6298 retransmission timer state: SRTT, RTTVAR and the current RTO.
#[derive(Debug, Clone, Copy)]
pub struct RTO {
    srtt: Option<Duration>, // None until the first measurement
    rttvar: Duration,
    rto: Duration,
}

impl RTO {
    pub const fn new() -> Self {
        RTO {
            srtt: None,
            rttvar: Duration::ZERO,
            rto: MIN,
        }
    }

    /// absolute deadline for the timer worker
    pub fn deadline(&self) -> Instant {
        Instant::now() + self.rto
    }

    pub fn rto(&self) -> Duration {
        self.rto
    }

    /// RFC 6298 §5.5, clamped to the cap
    pub fn backoff(&mut self) {
        self.rto = min(self.rto.saturating_mul(2), MAX);
    }

    pub fn cap_reached(&self) -> bool {
        self.rto >= MAX
    }

    /// back to initial state (no measurements, RTO = 1s)
    pub fn clear(&mut self) {
        *self = Self::new();
    }

    /// Feed an RTT sample. ONLY for ACKs of segments that weren't retransmitted (Karn).
    pub fn update(&mut self, sent: Instant, received: Instant) {
        let rtt = received.saturating_duration_since(sent);

        let (srtt, rttvar) = match self.srtt {
            None => (rtt, rtt / 2), // first measure, §2.2
            Some(srtt) => {
                // §2.3
                const ALPHA: f32 = 0.125;
                const BETA: f32 = 0.25;
                let rttvar = self.rttvar.mul_f32(1.0 - BETA) + srtt.abs_diff(rtt).mul_f32(BETA);
                let srtt = srtt.mul_f32(1.0 - ALPHA) + rtt.mul_f32(ALPHA);
                (srtt, rttvar)
            }
        };

        self.srtt = Some(srtt);
        self.rttvar = rttvar;
        self.rto =
            (srtt + max(Duration::from_millis(CLOCK_GRANULARITY), 4 * rttvar)).clamp(MIN, MAX);
        trace!(?self.srtt, ?self.rttvar, ?self.rto, "updated RTO");
    }
}

impl Default for RTO {
    fn default() -> Self {
        Self::new()
    }
}
