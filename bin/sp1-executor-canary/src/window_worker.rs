//! Window-based producer task.
//!
//! Watches the canary driver's MDBX tip; once `tip >= window_end`,
//! collects the window's per-block payload via `Driver::collect_blob_inputs`
//! (header-RLP + tx envelopes), builds the shared `BlobVerificationInput`
//! once, then for each block pulls the bincode `EthClientExecutorInput`
//! via `Driver::get_or_build_witness` and pushes a per-block
//! `ExecuteTask` into the bounded SP1 channel.
//!
//! When `skip_empty_blocks` is enabled, blocks with zero transactions
//! are NOT dispatched — instead the window worker marks them done in
//! the `CompletionTracker` directly (no SP1 work, no divergence row,
//! `canary_blocks_skipped_total++`). The strict-prefix watermark still
//! advances cleanly through them.
//!
//! Cursor (`last_canaried_block` in SQLite) is NOT written here —
//! `sp1_worker` writes it on each completion via the strict-prefix
//! watermark. That guarantees no in-flight blocks are skipped on
//! restart even if the canary crashes mid-window.

use std::{
    sync::{atomic::AtomicU64, Arc, Mutex},
    time::Duration,
};

use eyre::eyre;
use rusqlite::Connection;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use witness_orchestrator::driver::Driver;

use crate::{
    completion_tracker::CompletionTracker,
    db::write_last_canaried_block,
    types::{BlockExpected, ExecuteTask},
    verify::expected_versioned_hashes,
};

const POLL_INTERVAL: Duration = Duration::from_millis(500);

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run(
    driver: Arc<Driver>,
    tx: async_channel::Sender<ExecuteTask>,
    db: Arc<Mutex<Connection>>,
    consumer_tip: Arc<AtomicU64>,
    tracker: Arc<Mutex<CompletionTracker>>,
    start_cursor: u64,
    window_size: u64,
    skip_empty_blocks: bool,
    shutdown: CancellationToken,
) -> eyre::Result<()> {
    let mut window_start = start_cursor;
    info!(
        event = "window_worker_started",
        window_start, window_size, skip_empty_blocks, "canary window worker ready"
    );

    loop {
        if shutdown.is_cancelled() {
            return Ok(());
        }

        let mdbx_tip = match driver.mdbx_tip() {
            Some(t) => {
                crate::metrics::set_driver_mdbx_tip(t);
                t
            }
            None => {
                tokio::select! {
                    _ = shutdown.cancelled() => return Ok(()),
                    _ = tokio::time::sleep(POLL_INTERVAL) => continue,
                }
            }
        };

        let window_end = window_start + window_size - 1;
        if mdbx_tip < window_end {
            tokio::select! {
                _ = shutdown.cancelled() => return Ok(()),
                _ = tokio::time::sleep(POLL_INTERVAL) => continue,
            }
        }

        // Collect blob inputs separately so we keep per-block tx counts
        // for the empty-block skip path. Inlines what `build_blobs_from_mdbx`
        // does — one extra `iter().map(...)` is the only difference.
        let blocks = match driver.collect_blob_inputs(window_start..=window_end).await? {
            Some(b) => b,
            None => continue,
        };
        let tx_counts: Vec<usize> = blocks.iter().map(|b| b.tx_envelopes.len()).collect();
        let raw_blobs = rsp_blob_builder::build_blobs_from_fetched(blocks)?;

        let blob_input = rsp_blob_builder::prepare_blob_verification_input(&raw_blobs)?;
        let expected_vhashes = expected_versioned_hashes(&blob_input.commitments);
        let blob_input_bytes = Arc::new(bincode::serialize(&blob_input)?);

        let l2_headers = match driver.collect_l2_block_headers(window_start..=window_end).await? {
            Some((h, _leaves)) => h,
            None => continue,
        };

        for (offset, n) in (window_start..=window_end).enumerate() {
            if shutdown.is_cancelled() {
                return Ok(());
            }

            // Empty-block fast path: bypass SP1 entirely and mark done
            // in the tracker. The strict-prefix watermark advances
            // through these as if they had been canaried successfully.
            if skip_empty_blocks && tx_counts[offset] == 0 {
                let new_watermark = {
                    let mut t = tracker.lock().unwrap_or_else(|e| e.into_inner());
                    t.mark_done(n)
                };
                crate::metrics::count_block_skipped();
                if let Some(w) = new_watermark {
                    write_last_canaried_block(&db, w);
                    consumer_tip.fetch_max(w, std::sync::atomic::Ordering::Relaxed);
                    crate::metrics::set_last_block_canaried(w);
                }
                continue;
            }

            let (witness_bytes, _cert) = driver
                .get_or_build_witness(n)
                .await?
                .ok_or_else(|| eyre!("witness unavailable for block {n} despite tip ≥ {n}"))?;
            let h = &l2_headers[offset];
            let task = ExecuteTask {
                block_number: n,
                client_input: witness_bytes,
                blob_input: Arc::clone(&blob_input_bytes),
                expected: BlockExpected {
                    parent_hash: h.previousBlockHash,
                    block_hash: h.blockHash,
                    withdrawal_hash: h.withdrawalRoot,
                    deposit_hash: h.depositRoot,
                    versioned_hashes: Arc::clone(&expected_vhashes),
                },
            };
            if tx.send(task).await.is_err() {
                warn!(event = "window_worker_channel_closed", "SP1 channel closed — exiting");
                return Ok(());
            }
        }

        info!(
            event = "canary_window_dispatched",
            from_block = window_start,
            to_block = window_end,
            num_blobs = raw_blobs.len(),
            "window dispatched to SP1 workers"
        );
        window_start = window_end + 1;
    }
}
