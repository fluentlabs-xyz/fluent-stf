//! L1 event listener for batch lifecycle events.
//!
//! Polls the rollup contract on L1 for:
//! - `BatchCommitted(batchIndex, batchRoot, fromBlockHash, toBlockHash, numberOfBlocks,
//!   expectedBlobs)` — new batch declared (pre-upgrade variant `v0::BatchCommitted` with a single
//!   `lastBlockHash` is also matched for historical logs)
//! - `BatchSubmitted(batchIndex)` — all blobs submitted for the batch
//! - `BatchPreconfirmed(batchIndex, verifierContract, verifier)` — preconfirmation accepted
//! - `BatchReverted(fromBatchIndex)` — admin force-revert: orchestrator wipes state and restarts
//!   from the reverted batch index.
//!
//! Events are sent to the orchestrator via an mpsc channel.
//!
//! Contract ABI lives in `l1-rollup-client`.

use alloy_primitives::{Address, B256};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types::Filter;
use alloy_sol_types::SolEvent;
use eyre::{eyre, Result};
use l1_rollup_client::{
    BatchCommitted, BatchPreconfirmed, BatchReverted, BatchRootChallengeResolved,
    BatchRootChallenged, BatchSubmitted, BlockChallenged, ChallengeResolved,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Event types sent to orchestrator
// ---------------------------------------------------------------------------

/// Events the L1 listener sends to the orchestrator.
///
/// Variant names mirror the v1.0.0 contract event names 1:1.
#[derive(Debug)]
pub(crate) enum L1Event {
    /// `BatchCommitted` — a new batch has been declared on L1.
    BatchCommitted { batch_index: u64, from: u64, to: u64 },
    /// `BatchSubmitted` — all blobs for the batch have been submitted.
    BatchSubmitted { batch_index: u64 },
    /// `BatchPreconfirmed` — carries the real tx_hash and l1_block.
    BatchPreconfirmed { batch_index: u64, tx_hash: B256, l1_block: u64 },
    /// `BatchReverted` — admin force-reverted batches from `from_batch_index`
    /// onward. Orchestrator wipes its DB, persists `from_batch_index` as the
    /// next start batch and `l1_block` as the L1 checkpoint, then triggers a
    /// graceful shutdown so the startup path re-resolves the L2 checkpoint
    /// from L1.
    BatchReverted { from_batch_index: u64, l1_block: u64 },
    /// `BlockChallenged(batchIndex, commitment, challenger)` — a block
    /// dispute opened against a preconfirmed batch.
    BlockChallenged { batch_index: u64, commitment: B256 },
    /// `BatchRootChallenged(batchIndex)` — a batch-root dispute opened.
    BatchRootChallenged { batch_index: u64 },
    /// `ChallengeResolved(batchIndex, commitment, prover)` — block-level
    /// dispute resolved (by any prover, possibly us).
    ChallengeResolved { batch_index: u64, commitment: B256 },
    /// `BatchRootChallengeResolved(batchIndex, prover)` — batch-root
    /// dispute resolved by some prover.
    BatchRootChallengeResolved { batch_index: u64 },
    /// All events up to this L1 block have been sent.
    /// Orchestrator persists this as the L1 checkpoint.
    Checkpoint(u64),
}

// ---------------------------------------------------------------------------
// Listener loop
// ---------------------------------------------------------------------------

const MAX_POLL_BACKOFF_SECS: u64 = 120;

/// Number of consecutive successful poll cycles between heartbeat INFO
/// logs. With the default `poll_interval_secs = 12` (one L1 block),
/// 100 cycles ≈ 20 minutes between heartbeats — enough to confirm
/// liveness without flooding the operator log.
const CHECKPOINT_LOG_EVERY: u64 = 100;

const MIN_PAGE: u64 = 100;
const MAX_PAGE: u64 = 10_000;
const INITIAL_PAGE: u64 = 2_000;

fn is_too_many_results(err_msg: &str) -> bool {
    let s = err_msg.to_lowercase();
    s.contains("-32005") ||
        s.contains("limit exceeded") ||
        s.contains("too many results") ||
        s.contains("log response size exceeded") ||
        s.contains("query returned more than") ||
        s.contains("please limit your query") ||
        s.contains("range is too large")
}

/// Result of a single poll iteration.
enum PollOutcome {
    /// All pages processed successfully up to this block.
    Complete(u64),
    /// Some pages failed; progress saved up to this block.
    Partial(u64),
}

/// Run the L1 event listener loop.
///
/// Polls L1 logs starting from `from_block` and sends parsed events to `tx`.
/// This function runs forever.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run(
    l1_provider: RootProvider,
    l2_provider: RootProvider,
    contract_addr: Address,
    mut from_block: u64,
    poll_interval_secs: u64,
    safe_blocks: u64,
    tx: mpsc::Sender<L1Event>,
    shutdown: CancellationToken,
) -> eyre::Result<()> {
    info!(
        %contract_addr,
        from_block,
        poll_interval_secs,
        safe_blocks,
        "L1 listener started"
    );

    let mut backoff_secs = poll_interval_secs;
    let mut page_size: u64 = INITIAL_PAGE;
    let mut polls_since_log: u64 = 0;

    loop {
        if shutdown.is_cancelled() {
            info!("Shutdown requested — exiting listener");
            break;
        }
        // Secondary guard: if the consumer dropped the receiver without
        // going through the shutdown token, the Partial/Err retry cycle
        // would otherwise spin forever.
        if tx.is_closed() {
            warn!("L1 event channel closed — exiting listener");
            break;
        }

        match poll_once(
            &l1_provider,
            &l2_provider,
            contract_addr,
            from_block,
            safe_blocks,
            &mut page_size,
            &tx,
            &shutdown,
        )
        .await
        {
            Ok(PollOutcome::Complete(latest)) => {
                if tx.send(L1Event::Checkpoint(latest)).await.is_err() {
                    warn!(latest, "L1 event channel closed");
                    break;
                }
                from_block = latest + 1;
                backoff_secs = poll_interval_secs; // reset on full success
                polls_since_log += 1;
                if polls_since_log >= CHECKPOINT_LOG_EVERY {
                    info!(latest_l1_block = latest, "L1 listener checkpoint heartbeat");
                    polls_since_log = 0;
                }
            }
            Ok(PollOutcome::Partial(last_ok)) => {
                if tx.send(L1Event::Checkpoint(last_ok)).await.is_err() {
                    warn!(last_ok, "L1 event channel closed");
                    break;
                }
                from_block = last_ok + 1;
                // Escalate backoff — don't reset, we hit rate limits
                backoff_secs = (backoff_secs * 2).min(MAX_POLL_BACKOFF_SECS);
                warn!(from_block, backoff_secs, "Partial progress — backing off");
            }
            Err(e) => {
                warn!(err = %e, backoff_secs, "L1 poll failed — retrying");
                backoff_secs = (backoff_secs * 2).min(MAX_POLL_BACKOFF_SECS);
            }
        }

        tokio::select! {
            _ = shutdown.cancelled() => {
                info!("Shutdown requested mid-backoff — exiting listener");
                break;
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)) => {}
        }
    }

    info!("L1 listener exiting");
    Ok(())
}

/// Single poll iteration: fetch logs from `from_block` to latest, paginated.
/// Returns `Complete` on full success, `Partial` on page failure with progress saved.
#[allow(clippy::too_many_arguments)]
async fn poll_once(
    provider: &RootProvider,
    l2_provider: &RootProvider,
    contract_addr: Address,
    from_block: u64,
    safe_blocks: u64,
    page_size: &mut u64,
    tx: &mpsc::Sender<L1Event>,
    shutdown: &CancellationToken,
) -> Result<PollOutcome> {
    let raw_latest =
        provider.get_block_number().await.map_err(|e| eyre!("Failed to get latest block: {e}"))?;
    let latest_block = raw_latest.saturating_sub(safe_blocks);

    if from_block > latest_block {
        return Ok(PollOutcome::Complete(from_block.saturating_sub(1)));
    }

    let mut current = from_block;
    let mut last_ok = from_block.saturating_sub(1);

    while current <= latest_block {
        let page_end = (current + *page_size - 1).min(latest_block);

        match process_page(provider, l2_provider, contract_addr, current, page_end, tx).await {
            Ok(()) => {
                last_ok = page_end;
                current = page_end + 1;
                *page_size = (*page_size + 100).min(MAX_PAGE);
            }
            Err(e) if is_too_many_results(&format!("{e}")) => {
                if shutdown.is_cancelled() {
                    return Ok(PollOutcome::Partial(last_ok));
                }
                let prev = *page_size;
                *page_size = (*page_size / 2).max(MIN_PAGE);
                warn!(new_page_size = *page_size, "RPC log limit hit — shrinking page");
                // If already at MIN_PAGE and still hitting the limit, bail
                // with partial progress so the outer backoff can kick in —
                // otherwise we spin retrying the same range forever.
                if prev == MIN_PAGE {
                    warn!(
                        current,
                        page_end, "RPC limit hit at MIN_PAGE — returning partial progress"
                    );
                    return Ok(PollOutcome::Partial(last_ok));
                }
                continue;
            }
            Err(e) => {
                warn!(err = %e, current, page_end, "Page failed — returning partial progress");
                return Ok(PollOutcome::Partial(last_ok));
            }
        }
    }

    Ok(PollOutcome::Complete(latest_block))
}

/// Process a single page of blocks: fetch and emit all event types in one query.
async fn process_page(
    provider: &RootProvider,
    l2_provider: &RootProvider,
    contract_addr: Address,
    from: u64,
    to: u64,
    tx: &mpsc::Sender<L1Event>,
) -> Result<()> {
    let filter = Filter::new()
        .address(contract_addr)
        .event_signature(vec![
            BatchCommitted::SIGNATURE_HASH,
            BatchSubmitted::SIGNATURE_HASH,
            BatchPreconfirmed::SIGNATURE_HASH,
            BatchReverted::SIGNATURE_HASH,
            BlockChallenged::SIGNATURE_HASH,
            BatchRootChallenged::SIGNATURE_HASH,
            ChallengeResolved::SIGNATURE_HASH,
            BatchRootChallengeResolved::SIGNATURE_HASH,
        ])
        .from_block(from)
        .to_block(to);

    let logs = provider
        .get_logs(&filter)
        .await
        .map_err(|e| eyre!("Log query failed [{from}..{to}]: {e}"))?;

    for log in &logs {
        let topic0 = log.topic0().copied().unwrap_or_default();

        if topic0 == BatchCommitted::SIGNATURE_HASH {
            let event = BatchCommitted::decode_log_data(&log.inner.data).map_err(|e| {
                eyre!("Failed to decode BatchCommitted v1 at L1 block {:?}: {e}", log.block_number)
            })?;

            let batch_index = event
                .batchIndex
                .try_into()
                .map_err(|_| eyre!("batchIndex to big: {}", event.batchIndex))?;
            let from_hash = event.fromBlockHash;
            let to_hash = event.toBlockHash;

            let from_block = l2_provider
                .get_block_by_hash(from_hash)
                .await
                .map_err(|e| eyre!("L2 RPC failed to fetch fromBlockHash ({}): {}", from_hash, e))?
                .ok_or_else(|| eyre!("Block {} not found on L2 Node", from_hash))?;

            let from_block_number = from_block.header.number + 1;

            let to_block = l2_provider
                .get_block_by_hash(to_hash)
                .await
                .map_err(|e| eyre!("L2 RPC failed to fetch toBlockHash ({}): {}", to_hash, e))?
                .ok_or_else(|| eyre!("Block {} not found on L2 Node", to_hash))?;

            let to_block_number = to_block.header.number;

            info!(batch_index, from_block_number, to_block_number, "BatchCommitted event");

            if tx
                .send(L1Event::BatchCommitted {
                    batch_index,
                    from: from_block_number,
                    to: to_block_number,
                })
                .await
                .is_err()
            {
                return Err(eyre!("L1 event channel closed"));
            }
        } else if topic0 == BatchSubmitted::SIGNATURE_HASH {
            let event = BatchSubmitted::decode_log_data(&log.inner.data).map_err(|e| {
                eyre!("Failed to decode BatchSubmitted at L1 block {:?}: {e}", log.block_number)
            })?;
            let batch_index: u64 = event
                .batchIndex
                .try_into()
                .map_err(|_| eyre!("batchIndex overflow: {}", event.batchIndex))?;
            info!(batch_index, "BatchSubmitted event");
            if tx.send(L1Event::BatchSubmitted { batch_index }).await.is_err() {
                return Err(eyre!("L1 event channel closed"));
            }
        } else if topic0 == BatchPreconfirmed::SIGNATURE_HASH {
            let event = BatchPreconfirmed::decode_log_data(&log.inner.data).map_err(|e| {
                eyre!("Failed to decode BatchPreconfirmed at L1 block {:?}: {e}", log.block_number)
            })?;
            let batch_index: u64 = event
                .batchIndex
                .try_into()
                .map_err(|_| eyre!("batchIndex overflow: {}", event.batchIndex))?;
            let tx_hash = log
                .transaction_hash
                .ok_or_else(|| eyre!("BatchPreconfirmed log missing transaction_hash"))?;
            let l1_block = log
                .block_number
                .ok_or_else(|| eyre!("BatchPreconfirmed log missing block_number"))?;
            info!(batch_index, %tx_hash, l1_block, "BatchPreconfirmed event");
            if tx.send(L1Event::BatchPreconfirmed { batch_index, tx_hash, l1_block }).await.is_err()
            {
                return Err(eyre!("L1 event channel closed"));
            }
        } else if topic0 == BatchReverted::SIGNATURE_HASH {
            let event = BatchReverted::decode_log_data(&log.inner.data).map_err(|e| {
                eyre!("Failed to decode BatchReverted at L1 block {:?}: {e}", log.block_number)
            })?;
            let from_batch_index: u64 = event
                .fromBatchIndex
                .try_into()
                .map_err(|_| eyre!("fromBatchIndex overflow: {}", event.fromBatchIndex))?;
            let l1_block =
                log.block_number.ok_or_else(|| eyre!("BatchReverted log missing block_number"))?;
            info!(from_batch_index, l1_block, "BatchReverted event");
            if tx.send(L1Event::BatchReverted { from_batch_index, l1_block }).await.is_err() {
                return Err(eyre!("L1 event channel closed"));
            }
        } else if topic0 == BlockChallenged::SIGNATURE_HASH {
            let event = BlockChallenged::decode_log_data(&log.inner.data).map_err(|e| {
                eyre!("Failed to decode BlockChallenged at L1 block {:?}: {e}", log.block_number)
            })?;
            let batch_index: u64 = event
                .batchIndex
                .try_into()
                .map_err(|_| eyre!("batchIndex overflow: {}", event.batchIndex))?;
            let commitment = event.commitment;
            // observe_block_challenged emits a single info! line with the
            // computed deadline — no need for a separate event-only log here.
            if tx.send(L1Event::BlockChallenged { batch_index, commitment }).await.is_err() {
                return Err(eyre!("L1 event channel closed"));
            }
        } else if topic0 == BatchRootChallenged::SIGNATURE_HASH {
            let event = BatchRootChallenged::decode_log_data(&log.inner.data).map_err(|e| {
                eyre!(
                    "Failed to decode BatchRootChallenged at L1 block {:?}: {e}",
                    log.block_number
                )
            })?;
            let batch_index: u64 = event
                .batchIndex
                .try_into()
                .map_err(|_| eyre!("batchIndex overflow: {}", event.batchIndex))?;
            // observe_batch_root_challenged emits a single info! line with
            // the computed deadline — no need for a separate event-only log.
            if tx.send(L1Event::BatchRootChallenged { batch_index }).await.is_err() {
                return Err(eyre!("L1 event channel closed"));
            }
        } else if topic0 == ChallengeResolved::SIGNATURE_HASH {
            let event = ChallengeResolved::decode_log_data(&log.inner.data).map_err(|e| {
                eyre!("Failed to decode ChallengeResolved at L1 block {:?}: {e}", log.block_number)
            })?;
            let batch_index: u64 = event
                .batchIndex
                .try_into()
                .map_err(|_| eyre!("batchIndex overflow: {}", event.batchIndex))?;
            let commitment = event.commitment;
            info!(batch_index, %commitment, "ChallengeResolved event");
            if tx.send(L1Event::ChallengeResolved { batch_index, commitment }).await.is_err() {
                return Err(eyre!("L1 event channel closed"));
            }
        } else if topic0 == BatchRootChallengeResolved::SIGNATURE_HASH {
            let event =
                BatchRootChallengeResolved::decode_log_data(&log.inner.data).map_err(|e| {
                    eyre!(
                        "Failed to decode BatchRootChallengeResolved at L1 block {:?}: {e}",
                        log.block_number
                    )
                })?;
            let batch_index: u64 = event
                .batchIndex
                .try_into()
                .map_err(|_| eyre!("batchIndex overflow: {}", event.batchIndex))?;
            info!(batch_index, "BatchRootChallengeResolved event");
            if tx.send(L1Event::BatchRootChallengeResolved { batch_index }).await.is_err() {
                return Err(eyre!("L1 event channel closed"));
            }
        }
    }

    Ok(())
}
