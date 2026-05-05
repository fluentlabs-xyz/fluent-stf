//! Hot per-block-response cache. Source of truth for live response state;
//! `block_responses` SQLite table is the async-flushed durability backstop.
//! Crash loses the trailing un-flushed window; restart re-executes via
//! `Db::missing_blocks_for_unsent_batches` priority replay.
//!
//! All other batch state (the `batches` table) lives only in SQLite.
//! Workers query it directly each tick — see the predicate methods on `Db`.

use std::collections::HashMap;

use tokio::sync::mpsc;

use crate::{
    db::{AsyncOp, DbCommand},
    types::EthExecutionResponse,
};

#[derive(Debug)]
pub(crate) struct ResponseCache {
    responses: HashMap<u64, EthExecutionResponse>,
    db_tx: Option<mpsc::UnboundedSender<DbCommand>>,
}

impl ResponseCache {
    /// Initialise with previously persisted responses. Caller reads
    /// `block_responses` from SQLite once at startup and passes the
    /// vector. `db_tx` is used for write-through async DB writes from
    /// `insert` / `purge`.
    pub(crate) fn new(
        initial: Vec<EthExecutionResponse>,
        db_tx: mpsc::UnboundedSender<DbCommand>,
    ) -> Self {
        let responses = initial.into_iter().map(|r| (r.block_number, r)).collect();
        Self { responses, db_tx: Some(db_tx) }
    }

    pub(crate) fn contains(&self, block: u64) -> bool {
        self.responses.contains_key(&block)
    }

    /// True when every block in `[from, to]` is present in the cache.
    /// Linear in the range length; fine at typical batch sizes (tens of blocks).
    pub(crate) fn has_range(&self, from: u64, to: u64) -> bool {
        (from..=to).all(|b| self.responses.contains_key(&b))
    }

    pub(crate) fn get_range(&self, from: u64, to: u64) -> Vec<EthExecutionResponse> {
        (from..=to).filter_map(|b| self.responses.get(&b).cloned()).collect()
    }

    pub(crate) fn insert(&mut self, resp: EthExecutionResponse) {
        let block = resp.block_number;
        self.responses.insert(block, resp.clone());
        if let Some(tx) = &self.db_tx {
            if tx.send(DbCommand::Async(AsyncOp::SaveResponse(resp))).is_err() {
                metrics::counter!(crate::metrics::DB_WRITER_DROPPED_TOTAL).increment(1);
            }
        }
    }

    pub(crate) fn purge(&mut self, blocks: &[u64]) {
        for &b in blocks {
            self.responses.remove(&b);
        }
        if let Some(tx) = &self.db_tx {
            if tx.send(DbCommand::Async(AsyncOp::DeleteResponsesBatch(blocks.to_vec()))).is_err() {
                metrics::counter!(crate::metrics::DB_WRITER_DROPPED_TOTAL).increment(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;

    fn fake_response(block: u64) -> EthExecutionResponse {
        EthExecutionResponse {
            block_number: block,
            leaf: [0u8; 32],
            block_hash: B256::ZERO,
            signature: [0u8; 64],
        }
    }

    #[test]
    fn has_range_returns_true_only_for_complete_runs() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut cache = ResponseCache::new(vec![], tx);
        for b in 100..=104 {
            cache.insert(fake_response(b));
        }
        assert!(cache.has_range(100, 104));
        assert!(cache.has_range(101, 103));
        assert!(!cache.has_range(99, 104));
        assert!(!cache.has_range(100, 105));
    }

    /// Cache update must happen before the async DB enqueue so the
    /// signer's `has_range` gate (cache-based) never trails the DB.
    /// `insert` calls `self.responses.insert(...)` before `tx.send(...)`,
    /// so right after a single `insert` the cache contains the block
    /// AND the receiver has exactly one pending message.
    #[test]
    fn insert_writes_cache_before_db_enqueue() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut cache = ResponseCache::new(vec![], tx);
        cache.insert(fake_response(42));
        assert!(cache.contains(42), "cache must reflect insert immediately");
        let queued = rx.try_recv().expect("db_tx must have received SaveResponse");
        match queued {
            DbCommand::Async(AsyncOp::SaveResponse(r)) => assert_eq!(r.block_number, 42),
            _ => panic!("unexpected DB command"),
        }
        assert!(rx.try_recv().is_err(), "exactly one DB enqueue per insert");
    }
}
