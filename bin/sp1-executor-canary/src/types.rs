//! Shared types between the window worker and the SP1 worker pool.

use std::sync::Arc;

use alloy_primitives::B256;

pub(crate) struct ExecuteTask {
    pub(crate) block_number: u64,
    /// bincode(EthClientExecutorInput) — written verbatim into stdin slot 0.
    pub(crate) client_input: Vec<u8>,
    /// bincode(BlobVerificationInput) — shared across the whole window via
    /// `Arc`; written verbatim into stdin slot 1.
    pub(crate) blob_input: Arc<Vec<u8>>,
    pub(crate) expected: BlockExpected,
}

#[derive(Clone)]
pub(crate) struct BlockExpected {
    pub(crate) parent_hash: B256,
    pub(crate) block_hash: B256,
    pub(crate) withdrawal_hash: B256,
    pub(crate) deposit_hash: B256,
    /// Versioned hashes for the window's blob set, shared across all blocks.
    pub(crate) versioned_hashes: Arc<Vec<B256>>,
}
