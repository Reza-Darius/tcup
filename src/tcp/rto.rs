use std::{cmp::max, task::Poll};

use std::pin::Pin;
use std::time::Duration;

use crate::tcp::timer::CLOCK_GRAN;
use pin_project_lite::pin_project;
use tokio::time::Instant;
use tracing::trace;

pub const RTO_START: u64 = 1000; // miliseconds
pub const RTO_CAP: u64 = RTO_START * 60; // one minute

/// awating this object drives the timer
#[derive(Debug)]
pub struct RTO {
    inner: Pin<Box<RTOInner>>,
}

impl Future for RTO {
    type Output = ();

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.inner.as_mut().poll(cx)
    }
}

impl Default for RTO {
    fn default() -> Self {
        RTO::new()
    }
}

impl RTO {
    /// new RTO timer with a RTO of 1 second
    pub fn new() -> RTO {
        let rto = Duration::from_millis(RTO_START);
        RTO {
            inner: Box::pin(RTOInner {
                first_measure: true,
                srtt: Duration::from_millis(0),
                rttvar: Duration::from_millis(0),
                rto,
                sleep: tokio::time::sleep(rto),
            }),
        }
    }

    /// doubles the RTO
    pub fn add_backoff(&mut self) {
        let this = self.inner.as_mut().project();
        *this.rto *= 2;
    }

    /// completely resets the RTO, mainly to reuse the allocation
    pub fn clear(&mut self) {
        let this = self.inner.as_mut().project();
        let rto_default = Duration::from_millis(RTO_START);

        *this.first_measure = true;
        *this.rto = rto_default;
        *this.srtt = Duration::from_millis(0);
        *this.rttvar = Duration::from_millis(0);
        this.sleep.reset(Instant::now() + rto_default);
    }

    /// did we exceed the maxmium RTO?
    pub fn cap_reached(&self) -> bool {
        self.inner.rto >= Duration::from_millis(RTO_CAP)
    }

    /// resets the timer to the current set RTO
    pub fn reset_sleep(&mut self) {
        let this = self.inner.as_mut().project();
        this.sleep.reset(Instant::now() + *this.rto);
    }

    /// calculates the round trip measurements and sets the RTO
    ///
    /// a measurement should ONLY be taken for an ACK on a segment that wasnt retransmitted
    ///
    /// https://datatracker.ietf.org/doc/html/rfc6298#section-3
    pub fn calc_rto(&mut self, sent: Instant, receive: Instant) {
        let this = self.inner.as_mut().project();
        let rtt = receive - sent;

        if *this.first_measure {
            let srtt = rtt;
            let rttvar = rtt / 2;
            let rto_calc = srtt + max(Duration::from_millis(CLOCK_GRAN), 4 * rttvar);

            *this.srtt = srtt;
            *this.rttvar = rttvar;
            *this.rto = max(rto_calc, Duration::from_millis(RTO_START)); // round to 1 second
            *this.first_measure = false;
        } else {
            //[JK88]  Jacobson, V. and M. Karels, "Congestion Avoidance and Control"
            const ALPHA: f32 = 0.125;
            const BETA: f32 = 0.25;

            let rttvar = this.rttvar.mul_f32(1f32 - BETA) + this.srtt.abs_diff(rtt).mul_f32(BETA);
            let srtt = this.srtt.mul_f32(1f32 - ALPHA) + rtt.mul_f32(ALPHA);
            let rto_calc = srtt + max(Duration::from_millis(CLOCK_GRAN), 4 * rttvar);

            *this.srtt = srtt;
            *this.rttvar = rttvar;
            *this.rto = max(rto_calc, Duration::from_millis(RTO_START)); // round to 1 second
        };
        trace!(?this.srtt, ?this.rttvar, ?this.rto, "calculated RTO");
    }
}

/*
 * possible optimization: use global clock instead of individual tokio::sleep
 */

pin_project! {
    #[derive(Debug)]
    struct RTOInner {
        first_measure: bool,
        srtt: Duration,
        rttvar: Duration,
        rto: Duration,

        #[pin]
        sleep: tokio::time::Sleep,
    }
}

impl Future for RTOInner {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this.sleep.poll(cx) {
            Poll::Ready(_) => {
                trace!(?this.rto, "RTO fired after");
                Poll::Ready(())
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_first_measurement() {
        let mut rto = RTO::new();

        let now = Instant::now();
        let sent = now - Duration::from_millis(100);

        rto.calc_rto(sent, now);

        let inner = rto.inner.as_ref();
        // RFC 6298 §2.2: SRTT ← R
        assert_eq!(inner.srtt, Duration::from_millis(100));

        // RTTVAR ← R/2
        assert_eq!(inner.rttvar, Duration::from_millis(50));

        // RTO = SRTT + max(G, 4·RTTVAR) = 100 + max(G, 200)
        // With CLOCK_GRAN=1 ms → 100+200 = 300 ms, floored to RTO_START (1 s)
        assert_eq!(inner.rto, Duration::from_millis(RTO_START));

        // first_measure must be cleared so next call uses EWMA path
        assert!(!inner.first_measure);
    }

    #[tokio::test]
    async fn test_subsequent_measurement() {
        let mut rto = RTO::new(); // first_measure = true (after fix)

        let now = Instant::now();
        rto.calc_rto(now - Duration::from_millis(100), now); // seed

        // Feed a second sample
        rto.calc_rto(now - Duration::from_millis(120), now);

        let inner = rto.inner.as_ref();
        // RTTVAR = 0.75·50 + 0.25·|100−120| = 37.5 + 5.0 = 42.5 ms
        let expected_rttvar = Duration::from_micros(42_500);
        assert!(
            (inner.rttvar.as_micros() as i64 - expected_rttvar.as_micros() as i64).abs() < 200,
            "rttvar was {:?}, expected ~42.5 ms",
            inner.rttvar
        );

        // SRTT = 0.875·100 + 0.125·120 = 87.5 + 15.0 = 102.5 ms
        let expected_srtt = Duration::from_micros(102_500);
        assert!(
            (inner.srtt.as_micros() as i64 - expected_srtt.as_micros() as i64).abs() < 200,
            "srtt was {:?}, expected ~102.5 ms",
            inner.srtt
        );

        // RTO = 102.5 + max(G, 4·42.5) = 102.5 + 170 = 272.5 ms → floored to 1 s
        assert_eq!(inner.rto, Duration::from_millis(RTO_START));
    }

    #[tokio::test]
    async fn test_rto_above_floor() {
        // Simulate a link where RTT is 800 ms.
        // After the first measurement:
        //   srtt=800, rttvar=400
        //   rto = 800 + max(G, 1600) = 2400 ms  ← above the 1 s floor
        let mut rto = RTO::new();
        let now = Instant::now();
        rto.calc_rto(now - Duration::from_millis(800), now);

        assert!(
            rto.inner.rto > Duration::from_millis(RTO_START),
            "RTO should exceed floor on a slow link; got {:?}",
            rto.inner.rto
        );
        assert_eq!(rto.inner.rto, Duration::from_millis(2400));
    }
}
