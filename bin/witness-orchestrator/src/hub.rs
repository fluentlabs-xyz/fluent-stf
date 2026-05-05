//! Cold-only witness persistence backed by `redb`.
//!
//! Used by the embedded forward-driver to durably store witnesses for
//! re-execution lookups (enclave key rotation) and to survive orchestrator
//! restarts. Zstd-compressed, byte-capped, block-window retention.
//!
//! Writes come in two flavours:
//! - `push` — immediate single-block commit (re-witness path, witness-server miss path). Returns
//!   after `redb` fsync.
//! - `push_batched` — buffered commit for the tip-following path. Payloads are zstd-compressed into
//!   an in-memory buffer; once the buffer reaches `batch_size`, a single `redb` write txn persists
//!   the whole batch with one fsync. A crash before flush loses the buffered block numbers, which
//!   the driver rebuilds on restart via its re-witness fallback.

#![allow(clippy::result_large_err)]

use std::{path::PathBuf, sync::Arc};

use redb::{Database, ReadableTable, TableDefinition};
use tokio::sync::Mutex as AsyncMutex;
use tracing::{error, info};

use crate::types::ProveRequest;
const COLD_TABLE: TableDefinition<'_, u64, &[u8]> = TableDefinition::new("cold_witnesses");
const META_TABLE: TableDefinition<'_, &str, u64> = TableDefinition::new("cold_meta");
const TOTAL_BYTES_KEY: &str = "total_bytes";

/// Default batch size for tip-following cold writes. 128 blocks amortizes one
/// `redb` fsync across ~2 minutes of L2 production at 1 s/block, which on the
/// observed hardware removes redb from the per-block critical path.
pub(crate) const DEFAULT_COLD_BATCH_SIZE: usize = 32;

pub(crate) struct WitnessHub {
    db: Arc<Database>,
    retention_blocks: u64,
    batch_size: usize,
    /// Compressed payloads awaiting a batched commit. Flushed when
    /// `len >= batch_size` or by an explicit `flush_pending` call.
    buffer: AsyncMutex<Vec<(u64, Vec<u8>)>>,
}

impl std::fmt::Debug for WitnessHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WitnessHub").finish_non_exhaustive()
    }
}

impl WitnessHub {
    /// Open or create a cold witness database at `cold_file`.
    ///
    /// `retention_blocks` defines the window of retained blocks. On every
    /// successful commit (single or batched), entries with
    /// `block_number < highest_committed - retention_blocks` are removed in
    /// the same write transaction. `retention_blocks == 0` disables retention
    /// (archive mode).
    ///
    /// `batch_size` controls the tip-following buffered write path:
    /// `push_batched` flushes when the buffer reaches this length. Values `< 1`
    /// are clamped to `1` (degenerate but safe: every push flushes immediately).
    pub(crate) fn new(
        cold_file: PathBuf,
        retention_blocks: u64,
        batch_size: usize,
    ) -> eyre::Result<Self> {
        if let Some(parent) = cold_file.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    eyre::eyre!("failed to create cold witness dir {parent:?}: {e}")
                })?;
            }
        }
        let db = Database::create(&cold_file)
            .map_err(|e| eyre::eyre!("failed to open cold redb at {cold_file:?}: {e}"))?;

        {
            let write_txn =
                db.begin_write().map_err(|e| eyre::eyre!("begin_write on fresh cold db: {e}"))?;
            write_txn.open_table(COLD_TABLE).map_err(|e| eyre::eyre!("open COLD_TABLE: {e}"))?;
            write_txn.open_table(META_TABLE).map_err(|e| eyre::eyre!("open META_TABLE: {e}"))?;
            write_txn.commit().map_err(|e| eyre::eyre!("commit fresh cold schema: {e}"))?;
        }

        Ok(Self {
            db: Arc::new(db),
            retention_blocks,
            batch_size: batch_size.max(1),
            buffer: AsyncMutex::new(Vec::new()),
        })
    }

    /// Persist a single witness payload immediately. Returns after the redb
    /// commit (fsync). Used by the re-witness path and witness-server cold-miss
    /// rebuild, where batching would delay durability without benefit.
    pub(crate) async fn push(&self, block_number: u64, payload: &[u8]) -> eyre::Result<()> {
        let compressed = compress_payload(payload).await?;
        let entries = vec![(block_number, compressed)];
        self.commit_entries(entries).await
    }

    /// Persist a witness payload via the buffered tip-following path. Compresses
    /// inline on the blocking pool, appends to the buffer, and auto-flushes when
    /// the buffer reaches `batch_size`. On crash before flush the buffered
    /// blocks are lost from cold; the driver's re-witness fallback rebuilds them
    /// from MDBX on restart.
    pub(crate) async fn push_batched(&self, block_number: u64, payload: &[u8]) -> eyre::Result<()> {
        let compressed = compress_payload(payload).await?;
        let to_flush = {
            let mut buf = self.buffer.lock().await;
            buf.push((block_number, compressed));
            if buf.len() >= self.batch_size {
                Some(std::mem::take(&mut *buf))
            } else {
                None
            }
        };
        if let Some(entries) = to_flush {
            self.commit_entries(entries).await?;
        }
        Ok(())
    }

    /// Drain and commit any pending buffered entries. Safe to call on shutdown
    /// or at phase boundaries; no-op if the buffer is empty.
    pub(crate) async fn flush_pending(&self) -> eyre::Result<()> {
        let entries = {
            let mut buf = self.buffer.lock().await;
            if buf.is_empty() {
                return Ok(());
            }
            std::mem::take(&mut *buf)
        };
        self.commit_entries(entries).await
    }

    /// Remove every cold entry with key strictly greater than `target`. Returns
    /// `(removed_count, bytes_freed)`. Expected to be called at boot time
    /// before any `push` / `push_batched` activity — buffered entries are not
    /// considered. Updates `total_bytes` in the same redb transaction.
    pub(crate) async fn unwind_above(&self, target: u64) -> eyre::Result<(u64, u64)> {
        let db = Arc::clone(&self.db);
        let join = tokio::task::spawn_blocking(move || -> Result<(u64, u64), redb::Error> {
            let write_txn = db.begin_write()?;
            let (count, bytes) = {
                let mut cold = write_txn.open_table(COLD_TABLE)?;
                let mut meta = write_txn.open_table(META_TABLE)?;
                let stale: Vec<(u64, u64)> = cold
                    .range((target + 1)..)?
                    .filter_map(|r| r.ok().map(|(k, v)| (k.value(), v.value().len() as u64)))
                    .collect();
                let mut total_bytes = read_total_bytes(&meta)?;
                let mut bytes_freed = 0u64;
                for (k, size) in &stale {
                    cold.remove(*k)?;
                    total_bytes = total_bytes.saturating_sub(*size);
                    bytes_freed = bytes_freed.saturating_add(*size);
                }
                meta.insert(TOTAL_BYTES_KEY, total_bytes)?;
                (stale.len() as u64, bytes_freed)
            };
            write_txn.commit()?;
            Ok((count, bytes))
        })
        .await;

        match join {
            Ok(Ok(pair)) => Ok(pair),
            Ok(Err(e)) => Err(eyre::eyre!("cold unwind: {e}")),
            Err(e) => Err(eyre::eyre!("cold unwind spawn_blocking join: {e}")),
        }
    }

    /// Highest block number currently persisted to cold. Does NOT include
    /// buffered-but-unflushed entries — callers that need exact liveness
    /// should `flush_pending` first.
    ///
    /// Under window retention the newest row is never evicted, so
    /// `table.last()` is the resume point.
    pub(crate) fn last_committed_block(&self) -> eyre::Result<Option<u64>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(COLD_TABLE)?;
        let last = table.last()?.map(|(k, _)| k.value());
        Ok(last)
    }

    /// Look up a single witness by block number. Returns `None` if missing
    /// or on decode failure. Checks the in-memory buffer first so tip-following
    /// callers can read back their own recent writes before the batch flushes.
    pub(crate) async fn get_witness(&self, block_number: u64) -> Option<ProveRequest> {
        {
            let buf = self.buffer.lock().await;
            if let Some(compressed) =
                buf.iter().rev().find_map(
                    |(bn, c)| {
                        if *bn == block_number {
                            Some(c.clone())
                        } else {
                            None
                        }
                    },
                )
            {
                drop(buf);
                return tokio::task::spawn_blocking(move || -> Option<ProveRequest> {
                    let payload = zstd::decode_all(compressed.as_slice()).ok()?;
                    Some(ProveRequest { block_number, payload })
                })
                .await
                .ok()?;
            }
        }

        let db = Arc::clone(&self.db);
        tokio::task::spawn_blocking(move || -> Option<ProveRequest> {
            let read_txn = db.begin_read().ok()?;
            let table = read_txn.open_table(COLD_TABLE).ok()?;
            let compressed = table.get(block_number).ok()??.value().to_vec();
            let payload = zstd::decode_all(compressed.as_slice()).ok()?;
            Some(ProveRequest { block_number, payload })
        })
        .await
        .ok()?
    }

    async fn commit_entries(&self, entries: Vec<(u64, Vec<u8>)>) -> eyre::Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let db = Arc::clone(&self.db);
        let retention_blocks = self.retention_blocks;

        let join = tokio::task::spawn_blocking(move || -> eyre::Result<()> {
            commit_batch_blocking(&db, entries, retention_blocks)
                .map_err(|e| eyre::eyre!("commit_batch: {e}"))
        })
        .await;

        match join {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => {
                error!(err = %e, "Cold: witness commit failed");
                Err(e)
            }
            Err(e) => {
                error!(err = %e, "Cold: spawn_blocking join failed");
                Err(eyre::eyre!("spawn_blocking join: {e}"))
            }
        }
    }
}

async fn compress_payload(payload: &[u8]) -> eyre::Result<Vec<u8>> {
    let payload = payload.to_vec();
    tokio::task::spawn_blocking(move || zstd::encode_all(payload.as_slice(), 3))
        .await
        .map_err(|e| eyre::eyre!("zstd spawn_blocking join: {e}"))?
        .map_err(|e| eyre::eyre!("zstd encode: {e}"))
}

/// Commit a batch of `(block_number, compressed)` entries in one write txn:
/// insert all, prune stale entries below the retention window once using the
/// highest committed block as the anchor, update `total_bytes`, log a warning
/// if the size cap is exceeded.
fn commit_batch_blocking(
    db: &Database,
    entries: Vec<(u64, Vec<u8>)>,
    retention_blocks: u64,
) -> Result<(), redb::Error> {
    debug_assert!(!entries.is_empty());
    let batched = entries.len();
    let write_txn = db.begin_write()?;
    let highest_block;
    {
        let mut cold = write_txn.open_table(COLD_TABLE)?;
        let mut meta = write_txn.open_table(META_TABLE)?;

        let mut total_bytes = read_total_bytes(&meta)?;
        let mut highest = 0u64;
        for (block_number, compressed) in &entries {
            let compressed_len = compressed.len() as u64;
            // Replacing an existing entry must update `total_bytes` by net
            // delta, not by addition — otherwise retries / replays inflate
            // the counter.
            let prior_len: u64 =
                cold.get(*block_number)?.map(|v| v.value().len() as u64).unwrap_or(0);
            cold.insert(*block_number, compressed.as_slice())?;
            total_bytes = total_bytes.saturating_sub(prior_len).saturating_add(compressed_len);
            if *block_number > highest {
                highest = *block_number;
            }
        }

        // Retention: drop every entry with key < highest - retention_blocks in
        // the same write txn. `retention_blocks == 0` → archive mode, no-op.
        if retention_blocks > 0 {
            let cutoff = highest.saturating_sub(retention_blocks);
            if cutoff > 0 {
                let stale: Vec<(u64, u64)> = cold
                    .range(..cutoff)?
                    .filter_map(|r| r.ok().map(|(k, v)| (k.value(), v.value().len() as u64)))
                    .collect();
                for (k, size) in &stale {
                    cold.remove(*k)?;
                    total_bytes = total_bytes.saturating_sub(*size);
                }
                if !stale.is_empty() {
                    info!(highest, cutoff, pruned = stale.len(), batched, "Cold: retention prune");
                }
            }
        }

        meta.insert(TOTAL_BYTES_KEY, total_bytes)?;

        highest_block = highest;
    }
    write_txn.commit()?;
    info!(highest_block, batched, "Cold: committed");
    Ok(())
}

fn read_total_bytes(meta: &redb::Table<'_, &str, u64>) -> Result<u64, redb::Error> {
    Ok(meta.get(TOTAL_BYTES_KEY)?.map(|v| v.value()).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn unique_cold_file(tag: &str) -> PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/witness_hub_tests");
        let dir = base.join(format!("{tag}_{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("cold.redb")
    }

    #[tokio::test]
    async fn push_get_roundtrip() {
        let file = unique_cold_file("roundtrip");
        let hub = WitnessHub::new(file.clone(), 0, 1).unwrap();

        hub.push(42, &vec![7u8; 1024]).await.unwrap();

        let got = hub.get_witness(42).await.expect("block 42");
        assert_eq!(got.block_number, 42);
        assert_eq!(got.payload.len(), 1024);
        assert_eq!(got.payload[0], 7u8);

        drop(hub);
        let _ = std::fs::remove_file(&file);
    }

    #[tokio::test]
    async fn push_overwrite_preserves_total_bytes() {
        let file = unique_cold_file("overwrite");
        let hub = WitnessHub::new(file.clone(), 0, 1).unwrap();

        hub.push(1, &vec![7u8; 100_000]).await.unwrap();
        let total1 = {
            let txn = hub.db.begin_read().unwrap();
            txn.open_table(META_TABLE).unwrap().get(TOTAL_BYTES_KEY).unwrap().unwrap().value()
        };

        hub.push(1, &vec![9u8; 100_000]).await.unwrap();
        let total2 = {
            let txn = hub.db.begin_read().unwrap();
            txn.open_table(META_TABLE).unwrap().get(TOTAL_BYTES_KEY).unwrap().unwrap().value()
        };

        // Same block_number, same compressed size — total must not double.
        assert_eq!(total1, total2);

        drop(hub);
        let _ = std::fs::remove_file(&file);
    }

    #[tokio::test]
    async fn last_committed_block_tracks_highest_push() {
        let file = unique_cold_file("last_committed");
        let hub = WitnessHub::new(file.clone(), 0, 1).unwrap();

        assert_eq!(hub.last_committed_block().unwrap(), None);

        hub.push(10, &vec![1u8; 1024]).await.unwrap();
        assert_eq!(hub.last_committed_block().unwrap(), Some(10));

        hub.push(20, &vec![2u8; 1024]).await.unwrap();
        assert_eq!(hub.last_committed_block().unwrap(), Some(20));

        drop(hub);
        let _ = std::fs::remove_file(&file);
    }

    #[tokio::test]
    async fn survives_hub_drop_and_reopen() {
        let file = unique_cold_file("reopen");
        {
            let hub = WitnessHub::new(file.clone(), 0, 1).unwrap();
            for i in 1..=5u64 {
                hub.push(i, &vec![i as u8; 300 * 1024]).await.unwrap();
            }
        }

        let hub = WitnessHub::new(file.clone(), 0, 1).unwrap();
        let got = hub.get_witness(3).await.expect("block 3 in cold");
        assert_eq!(got.payload.len(), 300 * 1024);
        assert_eq!(got.payload[0], 3u8);

        drop(hub);
        let _ = std::fs::remove_file(&file);
    }

    #[tokio::test]
    async fn push_prunes_blocks_below_retention_window() {
        let file = unique_cold_file("retention");
        // retention = 3: push(N) removes entries with key < N - 3.
        let hub = WitnessHub::new(file.clone(), 3, 1).unwrap();

        for i in 1..=10u64 {
            hub.push(i, &vec![i as u8; 1024]).await.unwrap();
        }

        let read_txn = hub.db.begin_read().unwrap();
        let table = read_txn.open_table(COLD_TABLE).unwrap();
        // After push(10), cutoff = 7 → blocks 1..=6 gone, 7..=10 stay.
        for i in 1..=6u64 {
            assert!(table.get(i).unwrap().is_none(), "block {i} must be pruned");
        }
        for i in 7..=10u64 {
            assert!(table.get(i).unwrap().is_some(), "block {i} must remain");
        }

        drop(read_txn);
        drop(hub);
        let _ = std::fs::remove_file(&file);
    }

    #[tokio::test]
    async fn retention_zero_keeps_all() {
        let file = unique_cold_file("archive");
        let hub = WitnessHub::new(file.clone(), 0, 1).unwrap();

        for i in 1..=20u64 {
            hub.push(i, &vec![i as u8; 256]).await.unwrap();
        }

        let read_txn = hub.db.begin_read().unwrap();
        let table = read_txn.open_table(COLD_TABLE).unwrap();
        for i in 1..=20u64 {
            assert!(table.get(i).unwrap().is_some(), "archive mode must keep block {i}");
        }

        drop(read_txn);
        drop(hub);
        let _ = std::fs::remove_file(&file);
    }

    #[tokio::test]
    async fn push_prune_updates_total_bytes() {
        let file = unique_cold_file("prune_meta");
        let hub = WitnessHub::new(file.clone(), 3, 1).unwrap();

        for i in 1..=10u64 {
            hub.push(i, &vec![i as u8; 300 * 1024]).await.unwrap();
        }

        let read_txn = hub.db.begin_read().unwrap();
        let table = read_txn.open_table(COLD_TABLE).unwrap();
        let meta = read_txn.open_table(META_TABLE).unwrap();
        let sum: u64 =
            table.iter().unwrap().filter_map(|r| r.ok().map(|(_, v)| v.value().len() as u64)).sum();
        let total = meta.get(TOTAL_BYTES_KEY).unwrap().unwrap().value();
        assert_eq!(sum, total, "meta[total_bytes] must equal sum of remaining value lengths");

        drop(read_txn);
        drop(hub);
        let _ = std::fs::remove_file(&file);
    }

    #[tokio::test]
    async fn push_batched_buffers_until_full_then_flushes() {
        let file = unique_cold_file("batched_flush");
        let hub = WitnessHub::new(file.clone(), 0, 4).unwrap();

        // First 3 buffer only — cold store stays empty on disk.
        for i in 1..=3u64 {
            hub.push_batched(i, &vec![i as u8; 256]).await.unwrap();
        }
        assert_eq!(hub.last_committed_block().unwrap(), None);

        // 4th push hits batch_size → triggers flush.
        hub.push_batched(4, &vec![4u8; 256]).await.unwrap();
        assert_eq!(hub.last_committed_block().unwrap(), Some(4));

        for i in 1..=4u64 {
            let got = hub.get_witness(i).await.expect("flushed block");
            assert_eq!(got.block_number, i);
            assert_eq!(got.payload[0], i as u8);
        }

        drop(hub);
        let _ = std::fs::remove_file(&file);
    }

    #[tokio::test]
    async fn push_batched_buffered_entries_visible_via_get_witness() {
        let file = unique_cold_file("batched_read_own_writes");
        let hub = WitnessHub::new(file.clone(), 0, 128).unwrap();

        hub.push_batched(77, &vec![0xAB; 1024]).await.unwrap();
        // Not yet persisted.
        assert_eq!(hub.last_committed_block().unwrap(), None);
        // But readable from buffer.
        let got = hub.get_witness(77).await.expect("buffered block readable");
        assert_eq!(got.block_number, 77);
        assert_eq!(got.payload.len(), 1024);
        assert_eq!(got.payload[0], 0xAB);

        drop(hub);
        let _ = std::fs::remove_file(&file);
    }

    #[tokio::test]
    async fn flush_pending_commits_buffered_entries() {
        let file = unique_cold_file("flush_pending");
        let hub = WitnessHub::new(file.clone(), 0, 1024).unwrap();

        for i in 1..=5u64 {
            hub.push_batched(i, &vec![i as u8; 256]).await.unwrap();
        }
        assert_eq!(hub.last_committed_block().unwrap(), None);

        hub.flush_pending().await.unwrap();
        assert_eq!(hub.last_committed_block().unwrap(), Some(5));

        // Second flush is a no-op.
        hub.flush_pending().await.unwrap();

        drop(hub);
        let _ = std::fs::remove_file(&file);
    }

    #[tokio::test]
    async fn push_batched_retention_prune_runs_once_per_batch() {
        let file = unique_cold_file("batched_retention");
        // retention = 3, batch = 5 → after flush at highest=10 keep 7..=10.
        let hub = WitnessHub::new(file.clone(), 3, 5).unwrap();

        // Seed with some earlier persisted entries.
        for i in 1..=5u64 {
            hub.push(i, &vec![i as u8; 256]).await.unwrap();
        }
        // Then buffer 6..=10 via batched API — flush triggers on 10th push.
        for i in 6..=10u64 {
            hub.push_batched(i, &vec![i as u8; 256]).await.unwrap();
        }

        let read_txn = hub.db.begin_read().unwrap();
        let table = read_txn.open_table(COLD_TABLE).unwrap();
        for i in 1..=6u64 {
            assert!(table.get(i).unwrap().is_none(), "block {i} must be pruned");
        }
        for i in 7..=10u64 {
            assert!(table.get(i).unwrap().is_some(), "block {i} must remain");
        }

        drop(read_txn);
        drop(hub);
        let _ = std::fs::remove_file(&file);
    }
}
