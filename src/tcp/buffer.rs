pub const RCV_BUF_SIZE: usize = 512 << 10; // 512 * 1024 = 512 KiB

use crate::{Error, Result};

#[derive(Debug, Default)]
pub struct RcvBuffer(Vec<u8>);

impl RcvBuffer {
    pub fn new() -> Self {
        RcvBuffer(vec![0u8; RCV_BUF_SIZE])
    }

    pub fn insert(&mut self, data: &[u8], seq: u32, isn: u32) -> Result<()> {
        let idx = (isn - seq) as usize;
        if idx + data.len() > self.0.len() {
            return Err(Error::Unknown(
                "rcv buffer insert exceeds capacity".to_string(),
            ));
        }
        let slice = self.0.as_mut_slice();

        slice[idx..idx + data.len()].copy_from_slice(data);
        Ok(())
    }
}
