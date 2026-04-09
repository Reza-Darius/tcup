use std::cmp::max;
use std::collections::VecDeque;

use std::pin::Pin;
use std::time::Duration;

use crate::tcp::timer::{CLOCK_GRAN, RTO_CAP, RTO_START};
use pin_project_lite::pin_project;
use tokio::time::Instant;

/*
 A segment on the retransmission queue is fully acknowledged if the sum of its sequence number and length is less than or equal to the acknowledgment value in the incoming segment.

 Only segments that advance SND.NXT (i.e., consume sequence space) are tracked for retransmission.
*/

/// retransmission queue
#[derive(Debug, Default)]
pub struct RTQ(VecDeque<RTQEntry>);

impl RTQ {
    pub fn push(&mut self, elem: RTQEntry) {
        self.0.push_back(elem);
    }
    pub fn pop(&mut self) -> Option<RTQEntry> {
        self.0.pop_front()
    }
    pub fn peek(&self) -> Option<&RTQEntry> {
        self.0.front()
    }
    pub fn match_front(&self, seg: u32) -> bool {
        if let Some(elem) = self.peek() {
            return elem.seq == seg;
        }
        false
    }
}

#[derive(Debug, Default)]
pub struct RTQEntry {
    pub seq: u32,
    pub len: u16,
}

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
    pub fn new() -> RTO {
        let rto = Duration::from_secs(RTO_START);
        RTO {
            inner: Box::pin(RTOInner {
                first_measure: false,
                srtt: Duration::from_secs(0),
                rttvar: Duration::from_secs(0),
                rto,
                sleep: tokio::time::sleep(rto),
            }),
        }
    }

    /// doubles the RTO and resets the sleep timer
    pub fn backoff(&mut self) {
        let this = self.inner.as_mut().project();
        *this.rto *= 2;
        this.sleep.reset(Instant::now() + *this.rto);
    }

    /// resets the RTO completely, mainly to reuse the allocation
    fn reset(&mut self) {
        let this = self.inner.as_mut().project();
        let rto_default = Duration::from_millis(RTO_START);

        *this.first_measure = true;
        *this.rto = rto_default;
        *this.srtt = Duration::from_secs(0);
        *this.rttvar = Duration::from_secs(0);
        this.sleep.reset(Instant::now() + rto_default);
    }

    pub fn limit_reached(&self) -> bool {
        self.inner.rto >= Duration::from_secs(RTO_CAP)
    }

    /// takes the start and end time to reset the sleep timer with the new timer
    pub fn take_measurement(&mut self, send: Duration, receive: Duration) {
        let this = self.inner.as_mut().project();
        if *this.first_measure {
            let srtt = receive;
            let rttvar = receive / 2;

            *this.rto = srtt + max(Duration::from_millis(CLOCK_GRAN), 4 * rttvar);
        } else {
            // calc subsequent measures
            // alpha = 0.125
            // beta = 0.25
            // rttvar = (1 - beta) * rttvar + beta * abs(srtt - r)
            // srtt = (1 - alpha) * srtt + alpha * r
            // rto = srtt + max(g, 4*rttvar)
        }
        this.sleep.reset(Instant::now() + *this.rto);
    }
}

pin_project! {
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

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.project().sleep.poll(cx)
    }
}
