use serde::Serialize;
use std::{
    io::{Read, Write},
    time::Duration,
};
use vsock::{VsockListener, VsockStream};

use crate::nitro::MAX_FRAME_SIZE;

/// A helper structure to handle length-prefixed bincode communication over VSOCK.
/// Uses the global MAX_FRAME_SIZE constant to enforce security limits.
pub struct VsockChannel {
    stream: VsockStream,
}

impl VsockChannel {
    /// Creates a new channel from an existing VSOCK stream.
    pub fn new(stream: VsockStream) -> Self {
        Self { stream }
    }

    /// Applies a read timeout to the underlying vsock stream so the enclave
    /// cannot be pinned by a host that opens a connection and never sends.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> anyhow::Result<()> {
        self.stream
            .set_read_timeout(timeout)
            .map_err(|e| anyhow::anyhow!("Failed to set vsock read timeout: {e}"))
    }

    /// Applies a write timeout to the underlying vsock stream so the enclave
    /// cannot be pinned by a host that accepts bytes slowly (or not at all).
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> anyhow::Result<()> {
        self.stream
            .set_write_timeout(timeout)
            .map_err(|e| anyhow::anyhow!("Failed to set vsock write timeout: {e}"))
    }

    /// Helper method to wait for the next connection using an existing listener.
    /// This is the correct way to implement the "accept" logic.
    pub fn accept(listener: &VsockListener) -> anyhow::Result<Self> {
        let (stream, _) = listener
            .accept()
            .map_err(|e| anyhow::anyhow!("Failed to accept VSOCK connection: {}", e))?;

        Ok(Self::new(stream))
    }

    /// Serializes an object using Bincode and sends it.
    pub fn send_bincode<T: Serialize>(&mut self, response: &T) -> anyhow::Result<()> {
        let serialized = bincode::serialize(response)
            .map_err(|e| anyhow::anyhow!("Bincode serialization failed: {}", e))?;

        self.write_frame(&serialized)
    }

    /// Core logic for sending a length-prefixed frame over VSOCK.
    /// Handles length prefixing, writing, and flushing.
    fn write_frame(&mut self, data: &[u8]) -> anyhow::Result<()> {
        let len = u32::try_from(data.len()).map_err(|_| {
            anyhow::anyhow!("Outgoing frame size ({}) exceeds u32::MAX", data.len())
        })?;

        // 1. Send the 4-byte Big-Endian length prefix
        self.stream
            .write_all(&len.to_be_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to write length prefix: {}", e))?;

        // 2. Send the actual payload (JSON or Bincode)
        self.stream
            .write_all(data)
            .map_err(|e| anyhow::anyhow!("Failed to write payload: {}", e))?;

        // 3. Ensure all data is pushed through the buffer
        self.stream.flush().map_err(|e| anyhow::anyhow!("Failed to flush stream: {}", e))?;

        Ok(())
    }

    /// Reads a 4-byte length prefix and returns the raw payload bytes.
    /// Enforces the global MAX_FRAME_SIZE limit.
    pub fn receive(&mut self) -> anyhow::Result<Vec<u8>> {
        // 1. Read the length prefix
        let mut len_buf = [0u8; 4];
        self.stream
            .read_exact(&mut len_buf)
            .map_err(|e| anyhow::anyhow!("Failed to read length prefix: {}", e))?;

        let len = u32::from_be_bytes(len_buf) as usize;

        // 2. Safety check: Prevent memory exhaustion using the global constant
        if len > MAX_FRAME_SIZE {
            return Err(anyhow::anyhow!(
                "Incoming frame size ({} bytes) exceeds the maximum limit ({} bytes)",
                len,
                MAX_FRAME_SIZE
            ));
        }

        // 3. Read the payload into a buffer
        let mut buf = vec![0u8; len];
        self.stream
            .read_exact(&mut buf)
            .map_err(|e| anyhow::anyhow!("Failed to read payload: {}", e))?;

        Ok(buf)
    }
}
