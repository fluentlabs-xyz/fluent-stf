//! Hot per-block-response cache. Source of truth for live response state;
//! `block_responses` SQLite table is the async-flushed durability backstop.
//! Crash loses the trailing un-flushed window; restart re-executes via
//! `Db::missing_blocks_for_unsent_batches` priority replay.
//!
//! All other batch state (the `batches` table) lives only in SQLite.
//! Workers query it directly each tick — see the predicate methods on `Db`.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
    time::{Duration, Instant},
};

use tokio::sync::mpsc;
use tracing::warn;

use crate::{
    db::{AsyncOp, DbCommand},
    types::EthExecutionResponse,
};

/// Suppression window for the drop-event log. The first drop in any
/// non-overlapping window is logged with a `dropped_since_last_log` count of
/// any silently-suppressed drops accumulated during the previous window.
/// Subsequent drops within the same window increment the suppressed counter
/// without logging. This bounds log spam while preserving a Graylog
/// breadcrumb on the first drop after a quiet period.
const DROP_LOG_WINDOW: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub(crate) struct ResponseCache {
    responses: HashMap<u64, EthExecutionResponse>,
    db_tx: Option<mpsc::UnboundedSender<DbCommand>>,
    drop_throttle: DropThrottle,
}

#[derive(Debug)]
struct DropThrottle {
    last_log: Mutex<Option<Instant>>,
    suppressed: AtomicU64,
}

impl DropThrottle {
    fn new() -> Self {
        Self { last_log: Mutex::new(None), suppressed: AtomicU64::new(0) }
    }

    /// Records a drop. Returns `Some(suppressed_since_last_log)` when this
    /// drop should produce a log line; returns `None` when the drop is
    /// suppressed within the active window. The returned count is reset to
    /// zero on every emitted log so the next window starts fresh.
    fn observe(&self) -> Option<u64> {
        let mut last = self.last_log.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        match *last {
            None => {
                *last = Some(now);
                Some(0)
            }
            Some(prev) if now.duration_since(prev) >= DROP_LOG_WINDOW => {
                let n = self.suppressed.swap(0, Ordering::Relaxed);
                *last = Some(now);
                Some(n)
            }
            Some(_) => {
                self.suppressed.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }
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
        Self { responses, db_tx: Some(db_tx), drop_throttle: DropThrottle::new() }
    }

    pub(crate) fn contains(&self, block: u64) -> bool {
        self.responses.contains_key(&block)
    }

    /// Number of cached responses currently held in memory. Used at shutdown
    /// to report how many entries were drained without persistence.
    pub(crate) fn len(&self) -> usize {
        self.responses.len()
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
                if let Some(suppressed) = self.drop_throttle.observe() {
                    warn!(
                        block_number = block,
                        event = "block_response_cache_drop",
                        reason = "db_writer_closed",
                        op = "insert",
                        dropped_since_last_log = suppressed,
                        "block_response_cache drop"
                    );
                }
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
                if let Some(suppressed) = self.drop_throttle.observe() {
                    warn!(
                        purged = blocks.len(),
                        event = "block_response_cache_drop",
                        reason = "db_writer_closed",
                        op = "purge",
                        dropped_since_last_log = suppressed,
                        "block_response_cache drop"
                    );
                }
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
