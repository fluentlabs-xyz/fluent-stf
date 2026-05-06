//! SQLite persistence for orchestrator crash recovery.
//!
//! Single source of truth for batch lifecycle state: every batch has one row
//! in the `batches` table whose `status` field tracks the canonical L1
//! contract progression (`committed → accepted → dispatched → preconfirmed →
//! finalized`). The presence of `signature IS NOT NULL` records the local
//! milestone of `/sign-batch-root` succeeding; the dispatcher gates on this
//! before broadcasting `preconfirmBatch`.
//!
//! `block_responses` is the durability backstop for the in-memory hot cache
//! held by `ResponseCache` — async-batched writes amortize fsyncs; on crash
//! we lose the trailing un-flushed window and recover by replaying the
//! missing blocks via `Db::missing_blocks_for_unsent_batches` at startup.
//!
//! `meta` carries the two non-derivable scalars: `l1_checkpoint` (listener
//! resume point) and `start_batch_id` (BatchReverted recovery anchor).
//!
//! All writes go through the actor in `run_db_writer`. Async per-row writes
//! coalesce into one transaction per flush; sync writes run as their own
//! dedicated transaction with an awaited oneshot ack so the caller observes
//! durability before proceeding.

use std::{path::Path, sync::Arc, time::Duration};

use alloy_primitives::B256;
use rusqlite::{params, Connection, OptionalExtension, Result};
use tokio::{
    sync::{mpsc, oneshot},
    time::{interval, MissedTickBehavior},
};
use tracing::{error, info, warn};

use crate::types::{EthExecutionResponse, SubmitBatchResponse};

// ============================================================================
// RBF resume state — moved from accumulator.rs (part of the SQL surface)
// ============================================================================

/// State carried over from a prior process lifetime. Used by the dispatcher's
/// resume path to skip the initial broadcast and enter the bump loop directly.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RbfResumeState {
    pub(crate) nonce: u64,
    pub(crate) tx_hash: B256,
    pub(crate) max_fee_per_gas: u128,
    pub(crate) max_priority_fee_per_gas: u128,
}

// ============================================================================
// Status enum
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum BatchStatus {
    Committed = 0,
    Accepted = 1,
    Dispatched = 2,
    Preconfirmed = 3,
    Finalized = 4,
}

impl BatchStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Accepted => "accepted",
            Self::Dispatched => "dispatched",
            Self::Preconfirmed => "preconfirmed",
            Self::Finalized => "finalized",
        }
    }

    pub(crate) fn from_db(s: &str) -> Option<Self> {
        match s {
            "committed" => Some(Self::Committed),
            "accepted" => Some(Self::Accepted),
            "dispatched" => Some(Self::Dispatched),
            "preconfirmed" => Some(Self::Preconfirmed),
            "finalized" => Some(Self::Finalized),
            _ => None,
        }
    }
}

// ============================================================================
// Batch row + patch
// ============================================================================

#[derive(Debug, Clone)]
pub(crate) struct BatchRow {
    pub batch_index: u64,
    pub from_block: u64,
    pub to_block: u64,
    pub status: BatchStatus,
    pub signature: Option<SubmitBatchResponse>,
    pub tx_hash: Option<B256>,
    pub nonce: Option<u64>,
    pub max_fee_per_gas: Option<u128>,
    pub max_priority_fee_per_gas: Option<u128>,
    pub l1_block: Option<u64>,
    pub committed_at: u64,
    pub last_status_change_at: u64,
}

/// Sparse update — only fields the caller wants to change.
/// `None` → leave unchanged. `Some(None)` → set the column to NULL.
#[derive(Debug, Clone, Default)]
pub(crate) struct BatchPatch {
    pub status: Option<BatchStatus>,
    pub signature: Option<Option<SubmitBatchResponse>>,
    pub tx_hash: Option<Option<B256>>,
    pub nonce: Option<Option<u64>>,
    pub max_fee_per_gas: Option<Option<u128>>,
    pub max_priority_fee_per_gas: Option<Option<u128>>,
    pub l1_block: Option<Option<u64>>,
}

// ============================================================================
// Challenge enums + row + patch
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ChallengeKind {
    Block,
    BatchRoot,
}

impl ChallengeKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::BatchRoot => "batch_root",
        }
    }

    pub(crate) fn from_db(s: &str) -> Option<Self> {
        match s {
            "block" => Some(Self::Block),
            "batch_root" => Some(Self::BatchRoot),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum ChallengeStatus {
    Received = 0,
    Sp1Proving = 1,
    Sp1Proved = 2,
    Dispatched = 3,
    Resolved = 4,
    /// Terminal — challenge cannot be resolved (deadline expired,
    /// pre-broadcast simulation reverted, etc). Operator must call
    /// `revertBatches` on L1 to recover the rollup. The worker skips
    /// rows in this status.
    Failed = 5,
}

impl ChallengeStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Received => "received",
            Self::Sp1Proving => "sp1_proving",
            Self::Sp1Proved => "sp1_proved",
            Self::Dispatched => "dispatched",
            Self::Resolved => "resolved",
            Self::Failed => "failed",
        }
    }

    pub(crate) fn from_db(s: &str) -> Option<Self> {
        match s {
            "received" => Some(Self::Received),
            "sp1_proving" => Some(Self::Sp1Proving),
            "sp1_proved" => Some(Self::Sp1Proved),
            "dispatched" => Some(Self::Dispatched),
            "resolved" => Some(Self::Resolved),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ChallengeRow {
    pub challenge_id: i64,
    pub kind: ChallengeKind,
    pub batch_index: u64,
    pub commitment: Option<B256>,
    pub status: ChallengeStatus,
    pub deadline: u64,
    pub sp1_request_id: Option<B256>,
    pub sp1_proof_bytes: Option<Vec<u8>>,
    pub tx_hash: Option<B256>,
    pub nonce: Option<u64>,
    pub max_fee_per_gas: Option<u128>,
    pub max_priority_fee_per_gas: Option<u128>,
    pub l1_block: Option<u64>,
    pub committed_at: u64,
    pub last_status_change_at: u64,
    /// Unix-seconds timestamp of the most recent `/challenge/sp1/status`
    /// poll. `None` until the first poll. Used by the SQL predicate in
    /// `find_active_block_challenge` to skip rows still inside the
    /// `SP1_STATUS_POLL_INTERVAL_SECS` window — replaces the old
    /// in-handler `tokio::sleep` that was blocking the worker.
    pub last_polled_at: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ChallengePatch {
    pub status: Option<ChallengeStatus>,
    pub sp1_request_id: Option<Option<B256>>,
    pub sp1_proof_bytes: Option<Option<Vec<u8>>>,
    pub tx_hash: Option<Option<B256>>,
    pub nonce: Option<Option<u64>>,
    pub max_fee_per_gas: Option<Option<u128>>,
    pub max_priority_fee_per_gas: Option<Option<u128>>,
    pub l1_block: Option<Option<u64>>,
    pub last_polled_at: Option<Option<u64>>,
}

/// Pacing window for `/challenge/sp1/status` polls. Mirrored in
/// `challenge_resolver` as `SP1_STATUS_POLL_INTERVAL`.
pub(crate) const SP1_STATUS_POLL_INTERVAL_SECS: u64 = 15;

// ============================================================================
// Db handle
// ============================================================================

pub(crate) struct Db {
    pub(crate) conn: Connection,
}

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Db").finish_non_exhaustive()
    }
}

const SCHEMA_DDL: &str = "
    CREATE TABLE IF NOT EXISTS batches (
        batch_index              INTEGER PRIMARY KEY,
        from_block               INTEGER NOT NULL,
        to_block                 INTEGER NOT NULL,
        status                   TEXT    NOT NULL,
        signature                BLOB,
        tx_hash                  BLOB,
        nonce                    INTEGER,
        max_fee_per_gas          TEXT,
        max_priority_fee_per_gas TEXT,
        l1_block                 INTEGER,
        committed_at             INTEGER NOT NULL,
        last_status_change_at    INTEGER NOT NULL,
        CHECK (status IN ('committed','accepted','dispatched','preconfirmed','finalized'))
    );
    CREATE INDEX IF NOT EXISTS batches_status_idx ON batches(status);

    CREATE TABLE IF NOT EXISTS block_responses (
        block_number INTEGER PRIMARY KEY,
        response     BLOB    NOT NULL
    );

    CREATE TABLE IF NOT EXISTS meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS challenges (
        challenge_id              INTEGER PRIMARY KEY AUTOINCREMENT,
        kind                      TEXT    NOT NULL,
        batch_index               INTEGER NOT NULL,
        commitment                BLOB,
        status                    TEXT    NOT NULL,
        deadline                  INTEGER NOT NULL,
        sp1_request_id            BLOB,
        sp1_proof_bytes           BLOB,
        tx_hash                   BLOB,
        nonce                     INTEGER,
        max_fee_per_gas           TEXT,
        max_priority_fee_per_gas  TEXT,
        l1_block                  INTEGER,
        committed_at              INTEGER NOT NULL,
        last_status_change_at     INTEGER NOT NULL,
        last_polled_at            INTEGER,
        CHECK (kind IN ('block','batch_root')),
        CHECK (status IN ('received','sp1_proving','sp1_proved','dispatched','resolved','failed')),
        CHECK (kind = 'batch_root' OR commitment IS NOT NULL),
        CHECK (status != 'sp1_proving' OR sp1_request_id IS NOT NULL)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS challenges_block_uniq
        ON challenges(kind, batch_index, commitment)
        WHERE kind = 'block';
    CREATE UNIQUE INDEX IF NOT EXISTS challenges_batch_root_uniq
        ON challenges(kind, batch_index)
        WHERE kind = 'batch_root';
    CREATE INDEX IF NOT EXISTS challenges_active_idx
        ON challenges(kind, status, deadline);
";

/// Column list used by every `SELECT ... FROM challenges` in this module.
/// Order is consensus with `row_to_challenge_row` indices.
const CHALLENGE_COLS: &str = "challenge_id, kind, batch_index, commitment, status, deadline, \
     sp1_request_id, sp1_proof_bytes, tx_hash, nonce, \
     max_fee_per_gas, max_priority_fee_per_gas, l1_block, \
     committed_at, last_status_change_at, last_polled_at";

impl Db {
    /// Open or create the SQLite database at `path`.
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
        conn.execute_batch(SCHEMA_DDL)?;
        Ok(Self { conn })
    }

    /// In-memory test DB. Same schema as `Db::open` but never touches the
    /// filesystem and does not survive the test.
    #[cfg(test)]
    pub(crate) fn open_in_memory_for_test() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA_DDL)?;
        Ok(Self { conn })
    }

    // ── Meta scalars ──────────────────────────────────────────────────────────

    pub(crate) fn get_l1_checkpoint(&self) -> Option<u64> {
        self.conn
            .query_row("SELECT value FROM meta WHERE key = 'l1_checkpoint'", [], |row| {
                row.get::<_, String>(0)
            })
            .optional()
            .ok()
            .flatten()
            .and_then(|s| s.parse().ok())
    }

    pub(crate) fn save_l1_checkpoint(&self, block_number: u64) {
        if let Err(e) = self.conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('l1_checkpoint', ?1)",
            params![block_number.to_string()],
        ) {
            warn!(
                err = %e,
                event = "save_l1_checkpoint_failed",
                "save_l1_checkpoint failed — will retry next tick"
            );
        }
    }

    pub(crate) fn get_start_batch_id(&self) -> Option<u64> {
        self.conn
            .query_row("SELECT value FROM meta WHERE key = 'start_batch_id'", [], |row| {
                row.get::<_, String>(0)
            })
            .optional()
            .ok()
            .flatten()
            .and_then(|s| s.parse().ok())
    }

    pub(crate) fn clear_start_batch_id(&self) {
        if let Err(e) = self.conn.execute("DELETE FROM meta WHERE key = 'start_batch_id'", []) {
            warn!(
                err = %e,
                event = "clear_start_batch_id_failed",
                "clear_start_batch_id failed — will retry next tick"
            );
        }
    }

    // ── Derived scalars (computed from batches) ───────────────────────────────

    /// `MAX(to_block)` across rows whose status is at least `Dispatched`.
    /// Drives the L2 driver checkpoint upper bound on startup.
    pub(crate) fn highest_dispatched_to_block(&self) -> Option<u64> {
        self.conn
            .query_row(
                "SELECT MAX(to_block) FROM batches \
                 WHERE status IN ('dispatched','preconfirmed','finalized')",
                [],
                |row| row.get::<_, Option<i64>>(0),
            )
            .ok()
            .flatten()
            .map(|v| v as u64)
    }

    /// `MAX(to_block)` across rows with status `finalized`.
    pub(crate) fn highest_finalized_to_block(&self) -> Option<u64> {
        self.conn
            .query_row("SELECT MAX(to_block) FROM batches WHERE status = 'finalized'", [], |row| {
                row.get::<_, Option<i64>>(0)
            })
            .ok()
            .flatten()
            .map(|v| v as u64)
    }

    /// Snapshot of batch row counts grouped by status. Returned in the order
    /// the heartbeat worker logs them (committed → accepted → dispatched →
    /// preconfirmed → finalized). Missing statuses are reported as zero.
    pub(crate) fn batch_status_counts(&self) -> [(BatchStatus, u64); 5] {
        let mut counts: [(BatchStatus, u64); 5] = [
            (BatchStatus::Committed, 0),
            (BatchStatus::Accepted, 0),
            (BatchStatus::Dispatched, 0),
            (BatchStatus::Preconfirmed, 0),
            (BatchStatus::Finalized, 0),
        ];
        let mut stmt =
            match self.conn.prepare("SELECT status, COUNT(*) FROM batches GROUP BY status") {
                Ok(s) => s,
                Err(_) => return counts,
            };
        let rows = stmt.query_map([], |row| {
            let status: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            Ok((status, count))
        });
        if let Ok(iter) = rows {
            for r in iter.flatten() {
                if let Some(s) = BatchStatus::from_db(&r.0) {
                    if let Some(slot) = counts.iter_mut().find(|(t, _)| *t == s) {
                        slot.1 = r.1.max(0) as u64;
                    }
                }
            }
        }
        counts
    }

    /// Snapshot of active challenge row counts, broken down into rows that
    /// have not yet reached the terminal `Resolved` status. Returned as a
    /// single u64 so the heartbeat line stays compact; per-status detail
    /// lives in Prometheus.
    pub(crate) fn active_challenge_count(&self) -> u64 {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM challenges WHERE status NOT IN ('resolved', 'failed')",
                [],
                |row| row.get::<_, i64>(0),
            )
            .ok()
            .map(|v| v.max(0) as u64)
            .unwrap_or(0)
    }

    /// `MAX(block_number)` across `block_responses` rows. Used at startup to
    /// seed `orchestrator_tip` so that responses persisted in a prior run
    /// (which the steady-state feeder will skip via cache-hit, bypassing the
    /// per-block tip advance in `handle_block_result`) are accounted for in
    /// the initial tip.
    pub(crate) fn highest_responded_block(&self) -> Option<u64> {
        self.conn
            .query_row("SELECT MAX(block_number) FROM block_responses", [], |row| {
                row.get::<_, Option<i64>>(0)
            })
            .ok()
            .flatten()
            .map(|v| v as u64)
    }

    /// `MAX(nonce) + 1` across all batches that have a recorded nonce — the
    /// floor for the `NonceAllocator` bootstrap on startup.
    pub(crate) fn stored_nonce_floor(&self) -> Option<u64> {
        self.conn
            .query_row("SELECT MAX(nonce) FROM batches WHERE nonce IS NOT NULL", [], |row| {
                row.get::<_, Option<i64>>(0)
            })
            .ok()
            .flatten()
            .map(|v| (v as u64) + 1)
    }

    /// `tx_hash` of the row currently dispatched for `batch_index`, or `None`
    /// if the row is absent / has no `tx_hash`. Used by the finalization worker
    /// to detect stale ticker observations.
    pub(crate) fn dispatched_tx_hash(&self, batch_index: u64) -> Option<B256> {
        let blob: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT tx_hash FROM batches WHERE batch_index = ?1",
                params![batch_index as i64],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()
            .ok()
            .flatten()
            .flatten();
        B256::try_from(blob?.as_slice()).ok()
    }

    /// Block numbers absent from `block_responses` for any batch whose status
    /// is NOT IN ('dispatched','preconfirmed','finalized'). Returned in
    /// ascending order; called once at startup by `startup_recovery_feeder`.
    pub(crate) fn missing_blocks_for_unsent_batches(&self) -> Vec<u64> {
        let sql = "WITH RECURSIVE blocks(batch_index, block_number, to_block) AS ( \
                       SELECT batch_index, from_block, to_block FROM batches \
                       WHERE status NOT IN ('dispatched','preconfirmed','finalized') \
                     UNION ALL \
                       SELECT batch_index, block_number+1, to_block FROM blocks \
                       WHERE block_number+1 <= to_block \
                   ) \
                   SELECT block_number FROM blocks \
                   WHERE NOT EXISTS ( \
                       SELECT 1 FROM block_responses \
                       WHERE block_responses.block_number = blocks.block_number \
                   ) \
                   ORDER BY block_number";
        let mut stmt = match self.conn.prepare(sql) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    err = %e,
                    event = "db_prepare_failed",
                    op = "missing_blocks_for_unsent_batches",
                    "db prepare failed — will retry next tick"
                );
                return vec![];
            }
        };
        stmt.query_map([], |row| row.get::<_, i64>(0))
            .map(|iter| iter.filter_map(|r| r.ok()).map(|v| v as u64).collect())
            .unwrap_or_default()
    }

    // ── Batch read predicates (post-Q0: workers consume these directly) ─────

    /// Look up a single row by `batch_index`.
    pub(crate) fn find_batch(&self, batch_index: u64) -> Option<BatchRow> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT batch_index, from_block, to_block, status, \
                        signature, tx_hash, nonce, max_fee_per_gas, max_priority_fee_per_gas, \
                        l1_block, committed_at, last_status_change_at \
                 FROM batches WHERE batch_index = ?1",
            )
            .ok()?;
        stmt.query_row(params![batch_index as i64], row_to_batch_row).optional().ok().flatten()
    }

    /// Lowest-index batch ready for `/sign-batch-root`: status=accepted,
    /// `signature IS NULL`. Caller must additionally check
    /// `cache.has_range(from, to)` against the in-memory `ResponseCache` —
    /// gating on the SQL `block_responses` table would slip an extra writer-
    /// flush cycle (~100 ms per batch) of latency, since the cache is
    /// always ahead of the async-flushed DB rows.
    pub(crate) fn first_accepted_unsigned(&self) -> Option<u64> {
        self.conn
            .query_row(
                "SELECT b.batch_index FROM batches b \
                 WHERE b.status = 'accepted' AND b.signature IS NULL \
                 ORDER BY b.batch_index LIMIT 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .ok()
            .flatten()
            .map(|v| v as u64)
    }

    /// Lowest-index batch eligible for fresh dispatch — accepted +
    /// `signature IS NOT NULL`, with the strict-sequential gate of the L1
    /// contract: dispatchable only if either (a) the lowest-index batch
    /// itself is accepted+signed, or (b) the lowest-index batch has already
    /// moved past Dispatched (so we look for the next available).
    pub(crate) fn first_dispatchable(&self) -> Option<u64> {
        let first: Option<(u64, BatchStatus, bool)> = self
            .conn
            .query_row(
                "SELECT batch_index, status, (signature IS NOT NULL) FROM batches \
                 ORDER BY batch_index LIMIT 1",
                [],
                |row| {
                    let idx: i64 = row.get(0)?;
                    let status_str: String = row.get(1)?;
                    let signed: i64 = row.get(2)?;
                    Ok((
                        idx as u64,
                        BatchStatus::from_db(&status_str).unwrap_or(BatchStatus::Committed),
                        signed != 0,
                    ))
                },
            )
            .optional()
            .ok()
            .flatten();
        let (first_idx, first_status, first_signed) = first?;

        if first_status >= BatchStatus::Dispatched {
            // Lowest-index batch is past Dispatched → look for the next dispatchable.
            return self
                .conn
                .query_row(
                    "SELECT batch_index FROM batches \
                     WHERE status = 'accepted' AND signature IS NOT NULL \
                     ORDER BY batch_index LIMIT 1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
                .ok()
                .flatten()
                .map(|v| v as u64);
        }
        if first_status == BatchStatus::Accepted && first_signed {
            return Some(first_idx);
        }
        None
    }

    /// Lowest-index dispatched batch that has been broadcast but not yet
    /// mined (`status='dispatched' AND l1_block IS NULL`) — the dispatcher
    /// resumes its bump loop here. Once the receipt arrives `on_submitted`
    /// writes `l1_block`, after which the row falls out of this query and
    /// stays at Dispatched until the L1 listener observes the finalized
    /// `BatchPreconfirmed` event and transitions it to `Preconfirmed`.
    pub(crate) fn first_inflight_resume(&self) -> Option<(u64, Vec<u8>, RbfResumeState)> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT batch_index, signature, nonce, tx_hash, \
                        max_fee_per_gas, max_priority_fee_per_gas \
                 FROM batches \
                 WHERE status = 'dispatched' \
                   AND nonce IS NOT NULL AND tx_hash IS NOT NULL \
                   AND max_fee_per_gas IS NOT NULL AND max_priority_fee_per_gas IS NOT NULL \
                   AND signature IS NOT NULL \
                   AND l1_block IS NULL \
                 ORDER BY batch_index LIMIT 1",
            )
            .ok()?;
        stmt.query_row([], |row| {
            let batch_index: i64 = row.get(0)?;
            let sig_blob: Vec<u8> = row.get(1)?;
            let nonce: i64 = row.get(2)?;
            let tx_hash_blob: Vec<u8> = row.get(3)?;
            let max_fee: String = row.get(4)?;
            let max_priority: String = row.get(5)?;
            let sig: SubmitBatchResponse = bincode::deserialize(&sig_blob).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Blob,
                    Box::new(std::io::Error::other(format!("signature: {e}"))),
                )
            })?;
            let tx_hash = B256::try_from(tx_hash_blob.as_slice()).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    3,
                    rusqlite::types::Type::Blob,
                    Box::new(std::io::Error::other(format!("tx_hash: {e}"))),
                )
            })?;
            let resume = RbfResumeState {
                nonce: nonce as u64,
                tx_hash,
                max_fee_per_gas: max_fee.parse().unwrap_or(0),
                max_priority_fee_per_gas: max_priority.parse().unwrap_or(0),
            };
            Ok((batch_index as u64, sig.signature, resume))
        })
        .optional()
        .ok()
        .flatten()
    }

    /// Highest-index batch with status >= the given threshold, projected to
    /// the (batch_index, from_block, to_block) tuple used by metric seeders.
    pub(crate) fn find_highest_with_status_at_or_above(
        &self,
        threshold: BatchStatus,
    ) -> Option<BatchRow> {
        let allowed: &[&str] = match threshold {
            BatchStatus::Committed => {
                &["committed", "accepted", "dispatched", "preconfirmed", "finalized"]
            }
            BatchStatus::Accepted => &["accepted", "dispatched", "preconfirmed", "finalized"],
            BatchStatus::Dispatched => &["dispatched", "preconfirmed", "finalized"],
            BatchStatus::Preconfirmed => &["preconfirmed", "finalized"],
            BatchStatus::Finalized => &["finalized"],
        };
        let placeholders = vec!["?"; allowed.len()].join(",");
        let sql = format!(
            "SELECT batch_index, from_block, to_block, status, \
                    signature, tx_hash, nonce, max_fee_per_gas, max_priority_fee_per_gas, \
                    l1_block, committed_at, last_status_change_at \
             FROM batches \
             WHERE status IN ({placeholders}) \
             ORDER BY batch_index DESC LIMIT 1"
        );
        let mut stmt = self.conn.prepare(&sql).ok()?;
        let bind_refs: Vec<&dyn rusqlite::ToSql> =
            allowed.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        stmt.query_row(&bind_refs[..], row_to_batch_row).optional().ok().flatten()
    }

    /// Highest-index batch with `signature IS NOT NULL`, for the startup metric seed.
    pub(crate) fn find_highest_signed(&self) -> Option<BatchRow> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT batch_index, from_block, to_block, status, \
                        signature, tx_hash, nonce, max_fee_per_gas, max_priority_fee_per_gas, \
                        l1_block, committed_at, last_status_change_at \
                 FROM batches WHERE signature IS NOT NULL \
                 ORDER BY batch_index DESC LIMIT 1",
            )
            .ok()?;
        stmt.query_row([], row_to_batch_row).optional().ok().flatten()
    }

    /// Snapshot of all rows whose tx is mined on L1 (status=preconfirmed) —
    /// for the finalization worker to poll Ethereum chain finality.
    pub(crate) fn dispatched_for_finalization_check(&self) -> Vec<(u64, B256, u64)> {
        let mut stmt = match self.conn.prepare(
            "SELECT batch_index, tx_hash, l1_block FROM batches \
             WHERE status = 'preconfirmed' AND tx_hash IS NOT NULL AND l1_block IS NOT NULL",
        ) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    err = %e,
                    event = "db_prepare_failed",
                    op = "dispatched_for_finalization_check",
                    "db prepare failed — will retry next tick"
                );
                return vec![];
            }
        };
        stmt.query_map([], |row| {
            let idx: i64 = row.get(0)?;
            let tx_blob: Vec<u8> = row.get(1)?;
            let l1_block: i64 = row.get(2)?;
            let tx_hash = B256::try_from(tx_blob.as_slice()).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Blob,
                    Box::new(std::io::Error::other(format!("tx_hash: {e}"))),
                )
            })?;
            Ok((idx as u64, tx_hash, l1_block as u64))
        })
        .map(|iter| iter.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
    }

    // ── Batch table ──────────────────────────────────────────────────────────

    pub(crate) fn upsert_batch(&self, row: &BatchRow) -> Result<()> {
        let sig_blob = row.signature.as_ref().map(bincode::serialize).transpose().map_err(|e| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(format!(
                "serialize SubmitBatchResponse: {e}"
            ))))
        })?;
        self.conn.execute(
            "INSERT OR REPLACE INTO batches (\
                batch_index, from_block, to_block, status, \
                signature, tx_hash, nonce, max_fee_per_gas, max_priority_fee_per_gas, \
                l1_block, committed_at, last_status_change_at\
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![
                row.batch_index as i64,
                row.from_block as i64,
                row.to_block as i64,
                row.status.as_str(),
                sig_blob,
                row.tx_hash.as_ref().map(|h| h.0.to_vec()),
                row.nonce.map(|n| n as i64),
                row.max_fee_per_gas.map(|n| n.to_string()),
                row.max_priority_fee_per_gas.map(|n| n.to_string()),
                row.l1_block.map(|n| n as i64),
                row.committed_at as i64,
                row.last_status_change_at as i64,
            ],
        )?;
        Ok(())
    }

    pub(crate) fn patch_batch(&self, batch_index: u64, patch: &BatchPatch) -> Result<()> {
        let mut sets: Vec<&'static str> = Vec::new();
        let mut binds: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(s) = patch.status {
            sets.push("status = ?");
            binds.push(Box::new(s.as_str().to_string()));
            sets.push("last_status_change_at = ?");
            binds.push(Box::new(now_ts() as i64));
        }
        if let Some(ref sig_opt) = patch.signature {
            let sig_blob = sig_opt.as_ref().map(bincode::serialize).transpose().map_err(|e| {
                rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(format!(
                    "serialize signature: {e}"
                ))))
            })?;
            sets.push("signature = ?");
            binds.push(Box::new(sig_blob));
        }
        if let Some(tx) = patch.tx_hash {
            sets.push("tx_hash = ?");
            binds.push(Box::new(tx.map(|h| h.0.to_vec())));
        }
        if let Some(n) = patch.nonce {
            sets.push("nonce = ?");
            binds.push(Box::new(n.map(|v| v as i64)));
        }
        if let Some(f) = patch.max_fee_per_gas {
            sets.push("max_fee_per_gas = ?");
            binds.push(Box::new(f.map(|v| v.to_string())));
        }
        if let Some(f) = patch.max_priority_fee_per_gas {
            sets.push("max_priority_fee_per_gas = ?");
            binds.push(Box::new(f.map(|v| v.to_string())));
        }
        if let Some(b) = patch.l1_block {
            sets.push("l1_block = ?");
            binds.push(Box::new(b.map(|v| v as i64)));
        }
        if sets.is_empty() {
            return Ok(());
        }

        let sql = format!("UPDATE batches SET {} WHERE batch_index = ?", sets.join(", "));
        binds.push(Box::new(batch_index as i64));
        let bind_refs: Vec<&dyn rusqlite::ToSql> = binds.iter().map(|b| b.as_ref()).collect();
        self.conn.execute(&sql, &bind_refs[..])?;
        Ok(())
    }

    // ── block_responses ──────────────────────────────────────────────────────

    pub(crate) fn load_responses(&self) -> Vec<EthExecutionResponse> {
        let mut stmt =
            match self.conn.prepare("SELECT response FROM block_responses ORDER BY block_number") {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        err = %e,
                        event = "db_prepare_failed",
                        op = "load_responses",
                        "db prepare failed — will retry next tick"
                    );
                    return vec![];
                }
            };
        let blobs: Vec<Vec<u8>> = stmt
            .query_map([], |row| row.get(0))
            .map(|iter| iter.filter_map(|r| r.ok()).collect())
            .unwrap_or_default();
        blobs.into_iter().filter_map(|b| bincode::deserialize(&b).ok()).collect()
    }

    // ── Challenges table ─────────────────────────────────────────────────────

    /// `INSERT OR IGNORE` — idempotent on listener replay. Per-kind
    /// uniqueness is enforced by the partial unique indexes.
    pub(crate) fn insert_challenge(&self, row: &ChallengeRow) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO challenges (\
                kind, batch_index, commitment, status, deadline, \
                sp1_request_id, sp1_proof_bytes, \
                tx_hash, nonce, max_fee_per_gas, max_priority_fee_per_gas, \
                l1_block, committed_at, last_status_change_at, last_polled_at\
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
            params![
                row.kind.as_str(),
                row.batch_index as i64,
                row.commitment.as_ref().map(|h| h.0.to_vec()),
                row.status.as_str(),
                row.deadline as i64,
                row.sp1_request_id.as_ref().map(|h| h.0.to_vec()),
                row.sp1_proof_bytes.as_ref(),
                row.tx_hash.as_ref().map(|h| h.0.to_vec()),
                row.nonce.map(|n| n as i64),
                row.max_fee_per_gas.map(|n| n.to_string()),
                row.max_priority_fee_per_gas.map(|n| n.to_string()),
                row.l1_block.map(|n| n as i64),
                row.committed_at as i64,
                row.last_status_change_at as i64,
                row.last_polled_at.map(|n| n as i64),
            ],
        )?;
        Ok(())
    }

    pub(crate) fn patch_challenge(&self, challenge_id: i64, patch: &ChallengePatch) -> Result<()> {
        let mut sets: Vec<&'static str> = Vec::new();
        let mut binds: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(s) = patch.status {
            sets.push("status = ?");
            binds.push(Box::new(s.as_str().to_string()));
            sets.push("last_status_change_at = ?");
            binds.push(Box::new(now_ts() as i64));
        }
        if let Some(ref id) = patch.sp1_request_id {
            sets.push("sp1_request_id = ?");
            binds.push(Box::new(id.as_ref().map(|h| h.0.to_vec())));
        }
        if let Some(ref bytes) = patch.sp1_proof_bytes {
            sets.push("sp1_proof_bytes = ?");
            binds.push(Box::new(bytes.clone()));
        }
        if let Some(tx) = patch.tx_hash {
            sets.push("tx_hash = ?");
            binds.push(Box::new(tx.map(|h| h.0.to_vec())));
        }
        if let Some(n) = patch.nonce {
            sets.push("nonce = ?");
            binds.push(Box::new(n.map(|v| v as i64)));
        }
        if let Some(f) = patch.max_fee_per_gas {
            sets.push("max_fee_per_gas = ?");
            binds.push(Box::new(f.map(|v| v.to_string())));
        }
        if let Some(f) = patch.max_priority_fee_per_gas {
            sets.push("max_priority_fee_per_gas = ?");
            binds.push(Box::new(f.map(|v| v.to_string())));
        }
        if let Some(b) = patch.l1_block {
            sets.push("l1_block = ?");
            binds.push(Box::new(b.map(|v| v as i64)));
        }
        if let Some(p) = patch.last_polled_at {
            sets.push("last_polled_at = ?");
            binds.push(Box::new(p.map(|v| v as i64)));
        }
        if sets.is_empty() {
            return Ok(());
        }

        let sql = format!("UPDATE challenges SET {} WHERE challenge_id = ?", sets.join(", "));
        binds.push(Box::new(challenge_id));
        let bind_refs: Vec<&dyn rusqlite::ToSql> = binds.iter().map(|b| b.as_ref()).collect();
        self.conn.execute(&sql, &bind_refs[..])?;
        Ok(())
    }

    /// Block-worker gate: oldest non-terminal `kind=block` row, ordered by
    /// resolution deadline ASC (tiebreak: insertion order). Excludes the
    /// `dispatched`-but-mined window where the active worker has handed
    /// off ownership to the finalization ticker.
    pub(crate) fn find_active_block_challenge(&self) -> Option<ChallengeRow> {
        let now = now_ts() as i64;
        let poll_floor = now - SP1_STATUS_POLL_INTERVAL_SECS as i64;
        let sql = format!(
            "SELECT {CHALLENGE_COLS} FROM challenges \
             WHERE kind = 'block' \
               AND (status = 'received' \
                    OR (status = 'sp1_proving' \
                        AND (last_polled_at IS NULL OR last_polled_at <= ?1)) \
                    OR status = 'sp1_proved' \
                    OR (status = 'dispatched' AND l1_block IS NULL)) \
             ORDER BY deadline ASC, committed_at ASC \
             LIMIT 1"
        );
        let mut stmt = self.conn.prepare(&sql).ok()?;
        stmt.query_row(params![poll_floor], row_to_challenge_row).optional().ok().flatten()
    }

    /// BatchRoot-worker gate: oldest non-terminal `kind=batch_root` row,
    /// ordered by deadline ASC. BatchRoot rows do not transit `sp1_*`
    /// statuses (no SP1 round-trip), so the predicate is narrower than
    /// the block worker's.
    pub(crate) fn find_active_batch_root_challenge(&self) -> Option<ChallengeRow> {
        let sql = format!(
            "SELECT {CHALLENGE_COLS} FROM challenges \
             WHERE kind = 'batch_root' \
               AND (status = 'received' \
                    OR (status = 'dispatched' AND l1_block IS NULL)) \
             ORDER BY deadline ASC, committed_at ASC \
             LIMIT 1"
        );
        let mut stmt = self.conn.prepare(&sql).ok()?;
        stmt.query_row([], row_to_challenge_row).optional().ok().flatten()
    }

    pub(crate) fn find_challenge_by_id(&self, challenge_id: i64) -> Option<ChallengeRow> {
        let sql = format!("SELECT {CHALLENGE_COLS} FROM challenges WHERE challenge_id = ?1");
        let mut stmt = self.conn.prepare(&sql).ok()?;
        stmt.query_row(params![challenge_id], row_to_challenge_row).optional().ok().flatten()
    }

    /// Lookup for `ChallengeResolved` / `BatchRootChallengeResolved` event
    /// idempotency. For `Block` kind, `commitment` is required and matches
    /// exactly; for `BatchRoot` kind, `commitment` is ignored.
    pub(crate) fn find_challenge_by_event(
        &self,
        kind: ChallengeKind,
        batch_index: u64,
        commitment: Option<B256>,
    ) -> Option<ChallengeRow> {
        match kind {
            ChallengeKind::Block => {
                let c = commitment?;
                let sql = format!(
                    "SELECT {CHALLENGE_COLS} FROM challenges \
                     WHERE kind = 'block' AND batch_index = ?1 AND commitment = ?2"
                );
                let mut stmt = self.conn.prepare(&sql).ok()?;
                stmt.query_row(params![batch_index as i64, c.0.to_vec()], row_to_challenge_row)
                    .optional()
                    .ok()
                    .flatten()
            }
            ChallengeKind::BatchRoot => {
                let sql = format!(
                    "SELECT {CHALLENGE_COLS} FROM challenges \
                     WHERE kind = 'batch_root' AND batch_index = ?1"
                );
                let mut stmt = self.conn.prepare(&sql).ok()?;
                stmt.query_row(params![batch_index as i64], row_to_challenge_row)
                    .optional()
                    .ok()
                    .flatten()
            }
        }
    }

    /// Snapshot of dispatched rows whose receipt the finalization worker
    /// must reconcile against L1 (for reorg detection).
    pub(crate) fn dispatched_challenges_with_l1_block(&self) -> Vec<(i64, B256, u64)> {
        let mut stmt = match self.conn.prepare(
            "SELECT challenge_id, tx_hash, l1_block FROM challenges \
             WHERE status = 'dispatched' AND tx_hash IS NOT NULL AND l1_block IS NOT NULL",
        ) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    err = %e,
                    event = "db_prepare_failed",
                    op = "dispatched_challenges_with_l1_block",
                    "db prepare failed — will retry next tick"
                );
                return vec![];
            }
        };
        stmt.query_map([], |row| {
            let id: i64 = row.get(0)?;
            let tx_blob: Vec<u8> = row.get(1)?;
            let l1_block: i64 = row.get(2)?;
            let tx_hash = B256::try_from(tx_blob.as_slice()).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Blob,
                    Box::new(std::io::Error::other(format!("tx_hash B256: {e}"))),
                )
            })?;
            Ok((id, tx_hash, l1_block as u64))
        })
        .map(|iter| iter.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
    }

    // ── BatchReverted recovery ───────────────────────────────────────────────

    pub(crate) fn wipe_for_revert(&mut self, start_batch_id: u64, l1_block: u64) {
        let tx = match self.conn.transaction() {
            Ok(tx) => tx,
            Err(e) => {
                error!(
                    err = %e,
                    event = "wipe_for_revert_begin_failed",
                    "wipe_for_revert: begin tx failed"
                );
                return;
            }
        };
        let res = tx
            .execute_batch(
                "DELETE FROM batches; \
                 DELETE FROM block_responses; \
                 DELETE FROM challenges; \
                 DELETE FROM meta;",
            )
            .and_then(|()| {
                tx.execute(
                    "INSERT INTO meta(key, value) VALUES('start_batch_id', ?1)",
                    params![start_batch_id.to_string()],
                )
                .map(|_| ())
            })
            .and_then(|()| {
                tx.execute(
                    "INSERT INTO meta(key, value) VALUES('l1_checkpoint', ?1)",
                    params![l1_block.to_string()],
                )
                .map(|_| ())
            });
        match res {
            Ok(()) => {
                if let Err(e) = tx.commit() {
                    error!(
                        err = %e,
                        event = "wipe_for_revert_commit_failed",
                        "wipe_for_revert: commit failed"
                    );
                }
            }
            Err(e) => {
                error!(
                    err = %e,
                    event = "wipe_for_revert_statement_failed",
                    "wipe_for_revert: statement failed — rolling back"
                );
            }
        }
    }
}

fn row_to_batch_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<BatchRow> {
    let status_str: String = row.get(3)?;
    let status = BatchStatus::from_db(&status_str).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            3,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::other(format!("unknown batch status: {status_str}"))),
        )
    })?;
    let signature_blob: Option<Vec<u8>> = row.get(4)?;
    let signature = signature_blob
        .map(|b| bincode::deserialize::<SubmitBatchResponse>(&b))
        .transpose()
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                4,
                rusqlite::types::Type::Blob,
                Box::new(std::io::Error::other(format!("deserialize signature: {e}"))),
            )
        })?;
    let tx_hash_blob: Option<Vec<u8>> = row.get(5)?;
    let tx_hash = tx_hash_blob
        .map(|b| {
            B256::try_from(b.as_slice()).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    5,
                    rusqlite::types::Type::Blob,
                    Box::new(std::io::Error::other(format!("tx_hash B256: {e}"))),
                )
            })
        })
        .transpose()?;
    let nonce: Option<i64> = row.get(6)?;
    let max_fee: Option<String> = row.get(7)?;
    let max_priority: Option<String> = row.get(8)?;
    let l1_block: Option<i64> = row.get(9)?;
    let committed_at: i64 = row.get(10)?;
    let last_status_change_at: i64 = row.get(11)?;
    Ok(BatchRow {
        batch_index: row.get::<_, i64>(0)? as u64,
        from_block: row.get::<_, i64>(1)? as u64,
        to_block: row.get::<_, i64>(2)? as u64,
        status,
        signature,
        tx_hash,
        nonce: nonce.map(|n| n as u64),
        max_fee_per_gas: max_fee.and_then(|s| s.parse::<u128>().ok()),
        max_priority_fee_per_gas: max_priority.and_then(|s| s.parse::<u128>().ok()),
        l1_block: l1_block.map(|v| v as u64),
        committed_at: committed_at as u64,
        last_status_change_at: last_status_change_at as u64,
    })
}

fn row_to_challenge_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ChallengeRow> {
    let kind_str: String = row.get(1)?;
    let kind = ChallengeKind::from_db(&kind_str).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            1,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::other(format!("unknown challenge kind: {kind_str}"))),
        )
    })?;
    let commitment_blob: Option<Vec<u8>> = row.get(3)?;
    let commitment = commitment_blob
        .map(|b| {
            B256::try_from(b.as_slice()).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    3,
                    rusqlite::types::Type::Blob,
                    Box::new(std::io::Error::other(format!("commitment B256: {e}"))),
                )
            })
        })
        .transpose()?;
    let status_str: String = row.get(4)?;
    let status = ChallengeStatus::from_db(&status_str).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            4,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::other(format!("unknown challenge status: {status_str}"))),
        )
    })?;
    let deadline: i64 = row.get(5)?;
    let sp1_request_blob: Option<Vec<u8>> = row.get(6)?;
    let sp1_request_id = sp1_request_blob
        .map(|b| {
            B256::try_from(b.as_slice()).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    6,
                    rusqlite::types::Type::Blob,
                    Box::new(std::io::Error::other(format!("sp1_request_id B256: {e}"))),
                )
            })
        })
        .transpose()?;
    let sp1_proof_bytes: Option<Vec<u8>> = row.get(7)?;
    let tx_hash_blob: Option<Vec<u8>> = row.get(8)?;
    let tx_hash = tx_hash_blob
        .map(|b| {
            B256::try_from(b.as_slice()).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    8,
                    rusqlite::types::Type::Blob,
                    Box::new(std::io::Error::other(format!("tx_hash B256: {e}"))),
                )
            })
        })
        .transpose()?;
    let nonce: Option<i64> = row.get(9)?;
    let max_fee: Option<String> = row.get(10)?;
    let max_priority: Option<String> = row.get(11)?;
    let l1_block: Option<i64> = row.get(12)?;
    let committed_at: i64 = row.get(13)?;
    let last_status_change_at: i64 = row.get(14)?;
    let last_polled_at: Option<i64> = row.get(15)?;
    Ok(ChallengeRow {
        challenge_id: row.get::<_, i64>(0)?,
        kind,
        batch_index: row.get::<_, i64>(2)? as u64,
        commitment,
        status,
        deadline: deadline as u64,
        sp1_request_id,
        sp1_proof_bytes,
        tx_hash,
        nonce: nonce.map(|n| n as u64),
        max_fee_per_gas: max_fee.and_then(|s| s.parse::<u128>().ok()),
        max_priority_fee_per_gas: max_priority.and_then(|s| s.parse::<u128>().ok()),
        l1_block: l1_block.map(|v| v as u64),
        committed_at: committed_at as u64,
        last_status_change_at: last_status_change_at as u64,
        last_polled_at: last_polled_at.map(|v| v as u64),
    })
}

pub(crate) fn now_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ============================================================================
// DbCommand actor
// ============================================================================
//
// Async per-row writes coalesce into one transaction per flush (size threshold
// or 100 ms timer). Sync writes flush the per-row buffer first, run as their
// own dedicated transaction, then signal a oneshot so the caller observes
// durability. Caller-side helper: `db_send_sync(...).await`.

pub(crate) enum DbCommand {
    Async(AsyncOp),
    Sync(SyncOp, oneshot::Sender<()>),
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum AsyncOp {
    SaveResponse(EthExecutionResponse),
    DeleteResponsesBatch(Vec<u64>),
    SaveL1Checkpoint(u64),
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum SyncOp {
    PatchBatch {
        batch_index: u64,
        patch: BatchPatch,
    },
    /// `BatchCommitted` event. Inserts a new row at `Committed`. Idempotent:
    /// no-op if a row for `batch_index` already exists.
    ObserveCommitted {
        batch_index: u64,
        from_block: u64,
        to_block: u64,
    },
    /// `BatchSubmitted` event. Patches `Committed → Accepted`. Idempotent for
    /// rows already past `Accepted`. Logs `error!` if the row is missing — the
    /// contract semantics + chain-ordered listener guarantee `BatchCommitted`
    /// is observed first, so this branch is only reachable if that invariant
    /// breaks (contract upgrade, listener bug, manual DB intervention).
    ObserveSubmitted {
        batch_index: u64,
    },
    /// `BatchPreconfirmed` event. Branching is by `signature.is_some()`:
    ///   - row absent → insert at `Preconfirmed` (very early external batch);
    ///   - row already past `Preconfirmed` → idempotent no-op;
    ///   - `signature.is_some()` → "our batch": flip to `Preconfirmed`, preserve nonce/fees,
    ///     overwrite `l1_block`, set `tx_hash` only if currently NULL;
    ///   - `signature.is_none()` → "external takeover": set status, tx_hash, l1_block, NULL
    ///     nonce/fees.
    ObservePreconfirmed {
        batch_index: u64,
        tx_hash: B256,
        l1_block: u64,
    },
    /// L1 chain finality reached for our preconfirm tx.
    ObserveFinalized {
        batch_index: u64,
    },
    /// Reorg recovery: `Preconfirmed` → `Dispatched`, clear `l1_block`.
    /// No-op for external rows (`nonce IS NULL`) or rows past `Preconfirmed`.
    ObserveReorgToDispatched {
        batch_index: u64,
    },
    /// `Dispatched` → `Accepted`, clear RBF state. No-op for external rows or
    /// rows not at `Dispatched`.
    RollbackToAccepted {
        batch_index: u64,
    },
    /// Enclave key rotation: clear `signature`. Status unchanged.
    InvalidateSignature {
        batch_index: u64,
    },
    WipeForRevert {
        start_batch_id: u64,
        l1_block: u64,
    },
    InsertChallenge(ChallengeRow),
    PatchChallenge {
        challenge_id: i64,
        patch: ChallengePatch,
    },
}

const DB_BUFFER_FLUSH_SIZE: usize = 1000;
const DB_BUFFER_FLUSH_INTERVAL: Duration = Duration::from_millis(100);

pub(crate) async fn run_db_writer(
    mut rx: mpsc::UnboundedReceiver<DbCommand>,
    db: Arc<std::sync::Mutex<Db>>,
) {
    info!("DB writer actor started");
    let mut buffer: Vec<AsyncOp> = Vec::with_capacity(DB_BUFFER_FLUSH_SIZE);
    let mut ticker = interval(DB_BUFFER_FLUSH_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;
            maybe_cmd = rx.recv() => {
                match maybe_cmd {
                    Some(DbCommand::Sync(op, ack)) => {
                        flush_async_buffer(&db, &mut buffer);
                        run_sync_op(&db, op);
                        let _ = ack.send(());
                    }
                    Some(DbCommand::Async(op)) => {
                        buffer.push(op);
                        if buffer.len() >= DB_BUFFER_FLUSH_SIZE {
                            flush_async_buffer(&db, &mut buffer);
                        }
                    }
                    None => {
                        flush_async_buffer(&db, &mut buffer);
                        break;
                    }
                }
            }
            _ = ticker.tick() => {
                if !buffer.is_empty() {
                    flush_async_buffer(&db, &mut buffer);
                }
            }
        }
    }
    info!("DB writer actor exited");
}

fn flush_async_buffer(db: &Arc<std::sync::Mutex<Db>>, buffer: &mut Vec<AsyncOp>) {
    if buffer.is_empty() {
        return;
    }
    let drained: Vec<AsyncOp> = std::mem::take(buffer);
    let count = drained.len();
    let mut guard = db.lock().unwrap_or_else(|e| e.into_inner());
    let tx = match guard.conn.transaction() {
        Ok(t) => t,
        Err(e) => {
            warn!(
                err = %e,
                count,
                event = "db_begin_tx_failed",
                "db begin tx failed — batch dropped, will retry next tick"
            );
            return;
        }
    };
    for op in drained {
        apply_async_op(&tx, op);
    }
    if let Err(e) = tx.commit() {
        warn!(
            err = %e,
            count,
            event = "db_commit_failed",
            "db commit failed — batch lost, will retry next tick"
        );
    }
}

fn apply_async_op(tx: &rusqlite::Transaction<'_>, op: AsyncOp) {
    match op {
        AsyncOp::SaveResponse(resp) => {
            let blob = match bincode::serialize(&resp) {
                Ok(b) => b,
                Err(e) => {
                    error!(
                        err = %e,
                        event = "save_response_serialize_failed",
                        "save_response: serialize failed"
                    );
                    return;
                }
            };
            if let Err(e) = tx.execute(
                "INSERT OR REPLACE INTO block_responses(block_number, response) VALUES(?1, ?2)",
                params![resp.block_number as i64, blob],
            ) {
                warn!(
                    err = %e,
                    block_number = resp.block_number,
                    event = "save_response_failed",
                    "save_response failed — will retry next tick"
                );
            }
        }
        AsyncOp::DeleteResponsesBatch(blocks) => {
            for block in blocks {
                if let Err(e) = tx.execute(
                    "DELETE FROM block_responses WHERE block_number = ?1",
                    params![block as i64],
                ) {
                    warn!(
                        err = %e,
                        block_number = block,
                        event = "delete_response_failed",
                        "delete_response failed — will retry next tick"
                    );
                }
            }
        }
        AsyncOp::SaveL1Checkpoint(cp) => {
            if let Err(e) = tx.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES('l1_checkpoint', ?1)",
                params![cp.to_string()],
            ) {
                warn!(
                    err = %e,
                    cp,
                    event = "save_l1_checkpoint_failed",
                    "save_l1_checkpoint failed — will retry next tick"
                );
            }
        }
    }
}

fn run_sync_op(db: &Arc<std::sync::Mutex<Db>>, op: SyncOp) {
    let mut guard = db.lock().unwrap_or_else(|e| e.into_inner());
    match op {
        SyncOp::PatchBatch { batch_index, patch } => {
            if let Err(e) = guard.patch_batch(batch_index, &patch) {
                warn!(
                    err = %e,
                    batch_index,
                    event = "db_patch_failed",
                    op = "patch_batch",
                    "db patch failed — will retry next tick"
                );
            }
        }
        SyncOp::ObserveCommitted { batch_index, from_block, to_block } => {
            if guard.find_batch(batch_index).is_some() {
                return; // idempotent
            }
            let now = now_ts();
            let row = BatchRow {
                batch_index,
                from_block,
                to_block,
                status: BatchStatus::Committed,
                signature: None,
                tx_hash: None,
                nonce: None,
                max_fee_per_gas: None,
                max_priority_fee_per_gas: None,
                l1_block: None,
                committed_at: now,
                last_status_change_at: now,
            };
            if let Err(e) = guard.upsert_batch(&row) {
                warn!(
                    err = %e,
                    batch_index,
                    event = "db_upsert_failed",
                    op = "observe_committed",
                    "db upsert failed — will retry next tick"
                );
                return;
            }
            info!(
                batch_index,
                event = "batch_committed_observed",
                from_block,
                to_block,
                status = row.status.as_str(),
                "batch committed observed"
            );
        }
        SyncOp::ObserveSubmitted { batch_index } => match guard.find_batch(batch_index) {
            Some(b) if b.status == BatchStatus::Committed => {
                let patch =
                    BatchPatch { status: Some(BatchStatus::Accepted), ..Default::default() };
                if let Err(e) = guard.patch_batch(batch_index, &patch) {
                    warn!(
                        err = %e,
                        batch_index,
                        event = "db_patch_failed",
                        op = "observe_submitted",
                        "db patch failed — will retry next tick"
                    );
                    return;
                }
                info!(batch_index, event = "batch_accepted", "batch accepted");
            }
            Some(_) => { /* already past Accepted; idempotent no-op */ }
            None => {
                error!(
                    batch_index,
                    event = "observe_submitted_invariant_violation",
                    "observe_submitted with no prior BatchCommitted row — invariant violation \
                     (contract semantics + chain-ordered L1 listener guarantee BatchCommitted \
                     is observed first)"
                );
            }
        },
        SyncOp::ObservePreconfirmed { batch_index, tx_hash, l1_block } => {
            let row = guard.find_batch(batch_index);
            let now = now_ts();
            match row {
                // (a) idempotent — already past Preconfirmed
                Some(b) if b.status >= BatchStatus::Preconfirmed => {}
                // (b) "our batch" — we signed it, regardless of where in the lifecycle the
                //     listener catches up. Preserve any RBF state we may have written.
                Some(b) if b.signature.is_some() => {
                    let patch = BatchPatch {
                        status: Some(BatchStatus::Preconfirmed),
                        l1_block: Some(Some(l1_block)),
                        tx_hash: if b.tx_hash.is_none() { Some(Some(tx_hash)) } else { None },
                        ..Default::default()
                    };
                    if let Err(e) = guard.patch_batch(batch_index, &patch) {
                        warn!(
                            err = %e,
                            batch_index,
                            event = "db_patch_failed",
                            op = "observe_preconfirmed_local",
                            "db patch failed — will retry next tick"
                        );
                        return;
                    }
                    info!(
                        batch_index,
                        event = "batch_preconfirmed_local",
                        %tx_hash,
                        l1_block,
                        "batch preconfirmed via own broadcast"
                    );
                }
                // (c) external takeover — never seen in current production but kept for
                //     edge case (future second validator).
                Some(_) => {
                    let patch = BatchPatch {
                        status: Some(BatchStatus::Preconfirmed),
                        tx_hash: Some(Some(tx_hash)),
                        l1_block: Some(Some(l1_block)),
                        nonce: Some(None),
                        max_fee_per_gas: Some(None),
                        max_priority_fee_per_gas: Some(None),
                        ..Default::default()
                    };
                    if let Err(e) = guard.patch_batch(batch_index, &patch) {
                        warn!(
                            err = %e,
                            batch_index,
                            event = "db_patch_failed",
                            op = "observe_preconfirmed_external",
                            "db patch failed — will retry next tick"
                        );
                        return;
                    }
                    warn!(
                        batch_index,
                        event = "batch_preconfirmed_external",
                        %tx_hash,
                        l1_block,
                        "batch preconfirmed via external takeover"
                    );
                }
                // (d) row absent — insert at Preconfirmed (very early external batch).
                None => {
                    let row = BatchRow {
                        batch_index,
                        from_block: 0,
                        to_block: 0,
                        status: BatchStatus::Preconfirmed,
                        signature: None,
                        tx_hash: Some(tx_hash),
                        nonce: None,
                        max_fee_per_gas: None,
                        max_priority_fee_per_gas: None,
                        l1_block: Some(l1_block),
                        committed_at: now,
                        last_status_change_at: now,
                    };
                    if let Err(e) = guard.upsert_batch(&row) {
                        warn!(
                            err = %e,
                            batch_index,
                            event = "db_upsert_failed",
                            op = "observe_preconfirmed_insert",
                            "db upsert failed — will retry next tick"
                        );
                        return;
                    }
                    warn!(
                        batch_index,
                        event = "batch_preconfirmed_external",
                        %tx_hash,
                        l1_block,
                        reason = "no_prior_row",
                        "batch preconfirmed via external takeover (no prior row)"
                    );
                }
            }
        }
        SyncOp::ObserveFinalized { batch_index } => {
            let patch = BatchPatch { status: Some(BatchStatus::Finalized), ..Default::default() };
            if let Err(e) = guard.patch_batch(batch_index, &patch) {
                warn!(
                    err = %e,
                    batch_index,
                    event = "db_patch_failed",
                    op = "observe_finalized",
                    "db patch failed — will retry next tick"
                );
            }
        }
        SyncOp::ObserveReorgToDispatched { batch_index } => {
            let row = match guard.find_batch(batch_index) {
                Some(r) => r,
                None => return,
            };
            if row.status != BatchStatus::Preconfirmed {
                return;
            }
            if row.nonce.is_none() {
                info!(batch_index, "Skip reorg rollback: external dispatch (nonce=None)");
                return;
            }
            let patch = BatchPatch {
                status: Some(BatchStatus::Dispatched),
                l1_block: Some(None),
                ..Default::default()
            };
            if let Err(e) = guard.patch_batch(batch_index, &patch) {
                warn!(
                    err = %e,
                    batch_index,
                    event = "db_patch_failed",
                    op = "observe_reorg_to_dispatched",
                    "db patch failed — will retry next tick"
                );
            }
        }
        SyncOp::RollbackToAccepted { batch_index } => {
            let row = match guard.find_batch(batch_index) {
                Some(r) => r,
                None => return,
            };
            if row.nonce.is_none() {
                info!(batch_index, "Skip rollback: external dispatch (nonce=None)");
                return;
            }
            if row.status != BatchStatus::Dispatched {
                return;
            }
            let patch = BatchPatch {
                status: Some(BatchStatus::Accepted),
                tx_hash: Some(None),
                nonce: Some(None),
                max_fee_per_gas: Some(None),
                max_priority_fee_per_gas: Some(None),
                l1_block: Some(None),
                ..Default::default()
            };
            if let Err(e) = guard.patch_batch(batch_index, &patch) {
                warn!(
                    err = %e,
                    batch_index,
                    event = "db_patch_failed",
                    op = "rollback_to_accepted",
                    "db patch failed — will retry next tick"
                );
            }
        }
        SyncOp::InvalidateSignature { batch_index } => {
            let patch = BatchPatch { signature: Some(None), ..Default::default() };
            if let Err(e) = guard.patch_batch(batch_index, &patch) {
                warn!(
                    err = %e,
                    batch_index,
                    event = "db_patch_failed",
                    op = "invalidate_signature",
                    "db patch failed — will retry next tick"
                );
            }
        }
        SyncOp::WipeForRevert { start_batch_id, l1_block } => {
            guard.wipe_for_revert(start_batch_id, l1_block);
        }
        SyncOp::InsertChallenge(row) => {
            if let Err(e) = guard.insert_challenge(&row) {
                warn!(
                    err = %e,
                    batch_index = row.batch_index,
                    event = "db_insert_failed",
                    op = "insert_challenge",
                    "db insert failed — will retry next tick"
                );
            }
        }
        SyncOp::PatchChallenge { challenge_id, patch } => {
            if let Err(e) = guard.patch_challenge(challenge_id, &patch) {
                warn!(
                    err = %e,
                    challenge_id,
                    event = "db_patch_failed",
                    op = "patch_challenge",
                    "db patch failed — will retry next tick"
                );
            }
        }
    }
}

/// Send a sync write through the actor and await its ack.
/// Caller observes durability (one fsync) before returning.
pub(crate) async fn db_send_sync(
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    op: SyncOp,
) -> eyre::Result<()> {
    let (ack_tx, ack_rx) = oneshot::channel();
    db_tx.send(DbCommand::Sync(op, ack_tx)).map_err(|_| eyre::eyre!("db writer channel closed"))?;
    ack_rx.await.map_err(|_| eyre::eyre!("db writer dropped ack"))?;
    Ok(())
}

// ============================================================================
// Typed write wrappers — non-`db` modules call these instead of constructing
// `SyncOp` / `*Patch` directly.
// ============================================================================

// ── Batch ops ───────────────────────────────────────────────────────────────

pub(crate) async fn record_signature(
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    batch_index: u64,
    response: SubmitBatchResponse,
) -> eyre::Result<()> {
    let patch = BatchPatch { signature: Some(Some(response)), ..Default::default() };
    db_send_sync(db_tx, SyncOp::PatchBatch { batch_index, patch }).await
}

pub(crate) async fn invalidate_signature(
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    batch_index: u64,
) -> eyre::Result<()> {
    db_send_sync(db_tx, SyncOp::InvalidateSignature { batch_index }).await
}

pub(crate) async fn record_first_broadcast(
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    batch_index: u64,
    tx_hash: B256,
    nonce: u64,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
) -> eyre::Result<()> {
    let patch = BatchPatch {
        status: Some(BatchStatus::Dispatched),
        tx_hash: Some(Some(tx_hash)),
        nonce: Some(Some(nonce)),
        max_fee_per_gas: Some(Some(max_fee_per_gas)),
        max_priority_fee_per_gas: Some(Some(max_priority_fee_per_gas)),
        ..Default::default()
    };
    db_send_sync(db_tx, SyncOp::PatchBatch { batch_index, patch }).await
}

pub(crate) async fn record_rebroadcast(
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    batch_index: u64,
    tx_hash: B256,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
) -> eyre::Result<()> {
    let patch = BatchPatch {
        tx_hash: Some(Some(tx_hash)),
        max_fee_per_gas: Some(Some(max_fee_per_gas)),
        max_priority_fee_per_gas: Some(Some(max_priority_fee_per_gas)),
        ..Default::default()
    };
    db_send_sync(db_tx, SyncOp::PatchBatch { batch_index, patch }).await
}

/// Status stays `Dispatched` — the L1 listener owns the
/// `Dispatched → Preconfirmed` transition via `ObservePreconfirmed`.
pub(crate) async fn record_receipt_observed(
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    batch_index: u64,
    l1_block: u64,
) -> eyre::Result<()> {
    let patch = BatchPatch { l1_block: Some(Some(l1_block)), ..Default::default() };
    db_send_sync(db_tx, SyncOp::PatchBatch { batch_index, patch }).await
}

pub(crate) async fn observe_finalized(
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    batch_index: u64,
) -> eyre::Result<()> {
    db_send_sync(db_tx, SyncOp::ObserveFinalized { batch_index }).await
}

pub(crate) async fn observe_reorg_to_dispatched(
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    batch_index: u64,
) -> eyre::Result<()> {
    db_send_sync(db_tx, SyncOp::ObserveReorgToDispatched { batch_index }).await
}

pub(crate) async fn rollback_to_accepted(
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    batch_index: u64,
) -> eyre::Result<()> {
    db_send_sync(db_tx, SyncOp::RollbackToAccepted { batch_index }).await
}

pub(crate) async fn observe_committed(
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    batch_index: u64,
    from_block: u64,
    to_block: u64,
) -> eyre::Result<()> {
    db_send_sync(db_tx, SyncOp::ObserveCommitted { batch_index, from_block, to_block }).await
}

pub(crate) async fn observe_submitted(
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    batch_index: u64,
) -> eyre::Result<()> {
    db_send_sync(db_tx, SyncOp::ObserveSubmitted { batch_index }).await
}

pub(crate) async fn observe_preconfirmed(
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    batch_index: u64,
    tx_hash: B256,
    l1_block: u64,
) -> eyre::Result<()> {
    db_send_sync(db_tx, SyncOp::ObservePreconfirmed { batch_index, tx_hash, l1_block }).await
}

pub(crate) async fn wipe_for_revert(
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    start_batch_id: u64,
    l1_block: u64,
) -> eyre::Result<()> {
    db_send_sync(db_tx, SyncOp::WipeForRevert { start_batch_id, l1_block }).await
}

// ── Challenge ops ───────────────────────────────────────────────────────────

pub(crate) async fn insert_challenge(
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    row: ChallengeRow,
) -> eyre::Result<()> {
    db_send_sync(db_tx, SyncOp::InsertChallenge(row)).await
}

pub(crate) async fn record_challenge_resolved(
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    challenge_id: i64,
) -> eyre::Result<()> {
    let patch = ChallengePatch { status: Some(ChallengeStatus::Resolved), ..Default::default() };
    db_send_sync(db_tx, SyncOp::PatchChallenge { challenge_id, patch }).await
}

pub(crate) async fn record_challenge_failed(
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    challenge_id: i64,
) -> eyre::Result<()> {
    let patch = ChallengePatch { status: Some(ChallengeStatus::Failed), ..Default::default() };
    db_send_sync(db_tx, SyncOp::PatchChallenge { challenge_id, patch }).await
}

pub(crate) async fn record_challenge_sp1_requested(
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    challenge_id: i64,
    request_id: B256,
) -> eyre::Result<()> {
    let patch = ChallengePatch {
        status: Some(ChallengeStatus::Sp1Proving),
        sp1_request_id: Some(Some(request_id)),
        ..Default::default()
    };
    db_send_sync(db_tx, SyncOp::PatchChallenge { challenge_id, patch }).await
}

pub(crate) async fn record_challenge_sp1_proved(
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    challenge_id: i64,
    proof_bytes: Vec<u8>,
) -> eyre::Result<()> {
    let patch = ChallengePatch {
        status: Some(ChallengeStatus::Sp1Proved),
        sp1_proof_bytes: Some(Some(proof_bytes)),
        ..Default::default()
    };
    db_send_sync(db_tx, SyncOp::PatchChallenge { challenge_id, patch }).await
}

/// Proxy returned 404 for the request_id we held — reset to Received +
/// clear the request_id so the worker re-issues from scratch.
pub(crate) async fn record_challenge_sp1_lost_reset(
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    challenge_id: i64,
) -> eyre::Result<()> {
    let patch = ChallengePatch {
        status: Some(ChallengeStatus::Received),
        sp1_request_id: Some(None),
        ..Default::default()
    };
    db_send_sync(db_tx, SyncOp::PatchChallenge { challenge_id, patch }).await
}

/// Stamp `last_polled_at = now()` BEFORE the SP1 status RPC. The
/// `find_active_block_challenge` SQL excludes rows polled within the
/// poll-interval window, so stamping first prevents a tight retry loop
/// against the proxy if the RPC errors mid-flight.
pub(crate) async fn stamp_challenge_polled(
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    challenge_id: i64,
) -> eyre::Result<()> {
    let patch = ChallengePatch { last_polled_at: Some(Some(now_ts())), ..Default::default() };
    db_send_sync(db_tx, SyncOp::PatchChallenge { challenge_id, patch }).await
}

pub(crate) async fn record_challenge_first_broadcast(
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    challenge_id: i64,
    tx_hash: B256,
    nonce: u64,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
) -> eyre::Result<()> {
    let patch = ChallengePatch {
        status: Some(ChallengeStatus::Dispatched),
        tx_hash: Some(Some(tx_hash)),
        nonce: Some(Some(nonce)),
        max_fee_per_gas: Some(Some(max_fee_per_gas)),
        max_priority_fee_per_gas: Some(Some(max_priority_fee_per_gas)),
        ..Default::default()
    };
    db_send_sync(db_tx, SyncOp::PatchChallenge { challenge_id, patch }).await
}

pub(crate) async fn record_challenge_rebroadcast(
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    challenge_id: i64,
    tx_hash: B256,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
) -> eyre::Result<()> {
    let patch = ChallengePatch {
        tx_hash: Some(Some(tx_hash)),
        max_fee_per_gas: Some(Some(max_fee_per_gas)),
        max_priority_fee_per_gas: Some(Some(max_priority_fee_per_gas)),
        ..Default::default()
    };
    db_send_sync(db_tx, SyncOp::PatchChallenge { challenge_id, patch }).await
}

pub(crate) async fn record_challenge_submitted(
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    challenge_id: i64,
    l1_block: u64,
) -> eyre::Result<()> {
    let patch = ChallengePatch { l1_block: Some(Some(l1_block)), ..Default::default() };
    db_send_sync(db_tx, SyncOp::PatchChallenge { challenge_id, patch }).await
}

/// RBF state (nonce, fees, tx_hash) is intentionally preserved so the
/// active worker re-broadcasts the same signed tx against the new chain
/// canonicalisation. Only `l1_block` is cleared.
pub(crate) async fn clear_challenge_l1_block(
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    challenge_id: i64,
) -> eyre::Result<()> {
    let patch = ChallengePatch { l1_block: Some(None), ..Default::default() };
    db_send_sync(db_tx, SyncOp::PatchChallenge { challenge_id, patch }).await
}

pub(crate) async fn rollback_challenge_dispatch(
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    challenge_id: i64,
    rollback_status: ChallengeStatus,
) -> eyre::Result<()> {
    let patch = ChallengePatch {
        status: Some(rollback_status),
        tx_hash: Some(None),
        nonce: Some(None),
        max_fee_per_gas: Some(None),
        max_priority_fee_per_gas: Some(None),
        ..Default::default()
    };
    db_send_sync(db_tx, SyncOp::PatchChallenge { challenge_id, patch }).await
}

/// Contrast with `rollback_challenge_dispatch`: status is **not** changed
/// here. The L1 nonce was burned by the reverted tx; the worker re-runs
/// its lifecycle on the next tick (allocating a fresh nonce) without
/// regressing through the per-kind status transitions.
pub(crate) async fn clear_challenge_rbf_state_post_mine_revert(
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    challenge_id: i64,
) -> eyre::Result<()> {
    let patch = ChallengePatch {
        tx_hash: Some(None),
        nonce: Some(None),
        max_fee_per_gas: Some(None),
        max_priority_fee_per_gas: Some(None),
        l1_block: Some(None),
        ..Default::default()
    };
    db_send_sync(db_tx, SyncOp::PatchChallenge { challenge_id, patch }).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dispatched_row(batch_index: u64, l1_block: Option<u64>) -> BatchRow {
        BatchRow {
            batch_index,
            from_block: 100,
            to_block: 110,
            status: BatchStatus::Dispatched,
            signature: Some(SubmitBatchResponse {
                batch_root: vec![0u8; 32],
                versioned_hashes: vec![],
                signature: vec![0u8; 65],
            }),
            tx_hash: Some(B256::from([1u8; 32])),
            nonce: Some(7),
            max_fee_per_gas: Some(100),
            max_priority_fee_per_gas: Some(10),
            l1_block,
            committed_at: 0,
            last_status_change_at: 0,
        }
    }

    #[test]
    fn first_inflight_resume_returns_in_flight_row() {
        let db = Db::open_in_memory_for_test().unwrap();
        db.upsert_batch(&dispatched_row(1, None)).unwrap();
        let (idx, _, resume) = db.first_inflight_resume().expect("returns row");
        assert_eq!(idx, 1);
        assert_eq!(resume.nonce, 7);
    }

    #[test]
    fn first_inflight_resume_skips_mined_rows() {
        let db = Db::open_in_memory_for_test().unwrap();
        db.upsert_batch(&dispatched_row(1, Some(123))).unwrap();
        assert!(
            db.first_inflight_resume().is_none(),
            "Dispatched row with l1_block=Some must not be returned by the resume query"
        );
    }

    #[test]
    fn first_inflight_resume_picks_lowest_in_flight_when_mined_row_present() {
        let db = Db::open_in_memory_for_test().unwrap();
        db.upsert_batch(&dispatched_row(1, Some(123))).unwrap(); // mined, skipped
        db.upsert_batch(&dispatched_row(2, None)).unwrap(); // in-flight, returned
        let (idx, _, _) = db.first_inflight_resume().expect("returns row");
        assert_eq!(idx, 2);
    }

    fn challenge_row(
        kind: ChallengeKind,
        batch_index: u64,
        commitment: Option<B256>,
        status: ChallengeStatus,
        deadline: u64,
        sp1_request_id: Option<B256>,
        committed_at: u64,
    ) -> ChallengeRow {
        ChallengeRow {
            challenge_id: 0,
            kind,
            batch_index,
            commitment,
            status,
            deadline,
            sp1_request_id,
            sp1_proof_bytes: None,
            tx_hash: None,
            nonce: None,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            l1_block: None,
            committed_at,
            last_status_change_at: committed_at,
            last_polled_at: None,
        }
    }

    #[test]
    fn challenge_status_failed_persists_and_decodes() {
        let db = Db::open_in_memory_for_test().unwrap();
        // Insert a row in Received, then patch to Failed.
        let row = challenge_row(
            ChallengeKind::Block,
            1,
            Some(B256::from([1u8; 32])),
            ChallengeStatus::Received,
            42,
            None,
            0,
        );
        db.insert_challenge(&row).unwrap();
        let cid: i64 = db
            .conn
            .query_row("SELECT challenge_id FROM challenges LIMIT 1", [], |r| r.get(0))
            .unwrap();
        let patch = ChallengePatch { status: Some(ChallengeStatus::Failed), ..Default::default() };
        db.patch_challenge(cid, &patch).unwrap();
        let stored = db.find_challenge_by_id(cid).expect("row present");
        assert_eq!(stored.status, ChallengeStatus::Failed);
    }

    #[test]
    fn check_constraint_rejects_sp1_proving_without_request_id() {
        let db = Db::open_in_memory_for_test().unwrap();
        // Direct INSERT bypassing insert_challenge — exercises the SQL CHECK.
        let result = db.conn.execute(
            "INSERT INTO challenges (kind, batch_index, commitment, status, deadline, \
                                     committed_at, last_status_change_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params!["block", 1i64, vec![1u8; 32], "sp1_proving", 42i64, 0i64, 0i64,],
        );
        assert!(
            result.is_err(),
            "INSERT with status='sp1_proving' AND sp1_request_id=NULL must violate CHECK"
        );
    }

    #[test]
    fn find_active_block_challenge_skips_recently_polled() {
        let db = Db::open_in_memory_for_test().unwrap();
        let now = now_ts();
        let mut row = challenge_row(
            ChallengeKind::Block,
            1,
            Some(B256::from([0xAAu8; 32])),
            ChallengeStatus::Sp1Proving,
            1_000_000,
            Some(B256::from([0xBBu8; 32])),
            now,
        );
        row.last_polled_at = Some(now);
        db.insert_challenge(&row).unwrap();

        // Within poll interval → returns nothing.
        assert!(
            db.find_active_block_challenge().is_none(),
            "row polled within SP1_STATUS_POLL_INTERVAL_SECS must be excluded"
        );

        // Pull last_polled_at back beyond the window → row is eligible again.
        let cid: i64 = db
            .conn
            .query_row("SELECT challenge_id FROM challenges LIMIT 1", [], |r| r.get(0))
            .unwrap();
        let patch = ChallengePatch {
            last_polled_at: Some(Some(now - SP1_STATUS_POLL_INTERVAL_SECS - 1)),
            ..Default::default()
        };
        db.patch_challenge(cid, &patch).unwrap();
        assert!(
            db.find_active_block_challenge().is_some(),
            "row whose last_polled_at is older than the window must be returned"
        );
    }

    #[test]
    fn find_active_block_challenge_orders_by_deadline_asc() {
        let db = Db::open_in_memory_for_test().unwrap();
        // Two block challenges: A has earlier committed_at but later deadline,
        // B has later committed_at but earlier deadline. Ordering must
        // pick B first (deadline ASC overrides committed_at ASC).
        let a = challenge_row(
            ChallengeKind::Block,
            1,
            Some(B256::from([0xAAu8; 32])),
            ChallengeStatus::Received,
            /* deadline */ 200,
            None,
            /* committed_at */ 0,
        );
        let b = challenge_row(
            ChallengeKind::Block,
            2,
            Some(B256::from([0xBBu8; 32])),
            ChallengeStatus::Received,
            /* deadline */ 100,
            None,
            /* committed_at */ 5,
        );
        db.insert_challenge(&a).unwrap();
        db.insert_challenge(&b).unwrap();
        let row = db.find_active_block_challenge().expect("row returned");
        assert_eq!(row.batch_index, 2, "earlier-deadline row must be picked first");
    }

    #[test]
    fn find_active_batch_root_challenge_excludes_block_kind() {
        let db = Db::open_in_memory_for_test().unwrap();
        // Block-kind row is OLDER but should be invisible to the batch_root worker.
        let block_row = challenge_row(
            ChallengeKind::Block,
            1,
            Some(B256::from([0xAAu8; 32])),
            ChallengeStatus::Received,
            100,
            None,
            0,
        );
        let br_row = challenge_row(
            ChallengeKind::BatchRoot,
            2,
            None,
            ChallengeStatus::Received,
            200,
            None,
            5,
        );
        db.insert_challenge(&block_row).unwrap();
        db.insert_challenge(&br_row).unwrap();

        let row = db.find_active_batch_root_challenge().expect("row returned");
        assert_eq!(row.batch_index, 2);
        assert_eq!(row.kind, ChallengeKind::BatchRoot);
    }

    #[test]
    fn find_active_block_challenge_excludes_failed_and_resolved() {
        let db = Db::open_in_memory_for_test().unwrap();
        let failed_row = challenge_row(
            ChallengeKind::Block,
            1,
            Some(B256::from([0xAAu8; 32])),
            ChallengeStatus::Failed,
            100,
            None,
            0,
        );
        let resolved_row = challenge_row(
            ChallengeKind::Block,
            2,
            Some(B256::from([0xBBu8; 32])),
            ChallengeStatus::Resolved,
            150,
            None,
            5,
        );
        db.insert_challenge(&failed_row).unwrap();
        db.insert_challenge(&resolved_row).unwrap();
        assert!(
            db.find_active_block_challenge().is_none(),
            "Failed and Resolved rows must be excluded from the active gate"
        );
    }

    #[test]
    fn observe_committed_then_submitted_reaches_accepted_without_buffer() {
        let db = Db::open_in_memory_for_test().unwrap();
        let arc = Arc::new(std::sync::Mutex::new(db));

        run_sync_op(
            &arc,
            SyncOp::ObserveCommitted { batch_index: 5, from_block: 100, to_block: 110 },
        );
        {
            let g = arc.lock().unwrap();
            let row = g.find_batch(5).expect("row inserted");
            assert_eq!(row.status, BatchStatus::Committed);
            assert!(row.signature.is_none());
        }

        run_sync_op(&arc, SyncOp::ObserveSubmitted { batch_index: 5 });
        {
            let g = arc.lock().unwrap();
            let row = g.find_batch(5).expect("row still present");
            assert_eq!(row.status, BatchStatus::Accepted);
        }
    }
}
