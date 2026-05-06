//! L1-event-driven writes for the challenge state machine. Computes
//! per-row deadline locally from `getBatch(batchIndex)` (returns
//! `acceptedAtBlock` + the snapshotted `challengeWindow`) — the rollup
//! contract has no flat-tuple `getChallenge` view. Retries L1 RPC
//! failures indefinitely: a sustained L1 outage stalls listener
//! ingestion (correct outcome — never advance `l1_checkpoint` past an
//! event we couldn't persist).

use std::{sync::Arc, time::Duration};

use alloy_primitives::{Address, B256};
use alloy_provider::Provider;
use l1_rollup_client::BatchOnChain;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::db::{self, now_ts, ChallengeKind, ChallengeRow, ChallengeStatus, Db, DbCommand};

pub(crate) async fn observe_block_challenged(
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    l1_provider: &impl Provider,
    contract_addr: Address,
    batch_index: u64,
    commitment: B256,
    shutdown: &CancellationToken,
) -> eyre::Result<()> {
    let batch = get_batch_with_retry(l1_provider, contract_addr, batch_index, shutdown).await?;
    let deadline = batch.accepted_at_block + batch.challenge_window_snapshot;
    info!(
        kind = ChallengeKind::Block.as_str(),
        batch_index,
        %commitment,
        accepted_at_block = batch.accepted_at_block,
        challenge_window_snapshot = batch.challenge_window_snapshot,
        deadline,
        "Persisting block challenge with locally-computed deadline"
    );
    let now = now_ts();
    let row = ChallengeRow {
        challenge_id: 0,
        kind: ChallengeKind::Block,
        batch_index,
        commitment: Some(commitment),
        status: ChallengeStatus::Received,
        deadline,
        sp1_request_id: None,
        sp1_proof_bytes: None,
        tx_hash: None,
        nonce: None,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        l1_block: None,
        committed_at: now,
        last_status_change_at: now,
        last_polled_at: None,
    };
    db::insert_challenge(db_tx, row).await
}

pub(crate) async fn observe_batch_root_challenged(
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    l1_provider: &impl Provider,
    contract_addr: Address,
    batch_index: u64,
    shutdown: &CancellationToken,
) -> eyre::Result<()> {
    let batch = get_batch_with_retry(l1_provider, contract_addr, batch_index, shutdown).await?;
    let deadline = batch.accepted_at_block + batch.challenge_window_snapshot;
    info!(
        kind = ChallengeKind::BatchRoot.as_str(),
        batch_index,
        accepted_at_block = batch.accepted_at_block,
        challenge_window_snapshot = batch.challenge_window_snapshot,
        deadline,
        "Persisting batch-root challenge with locally-computed deadline"
    );
    let now = now_ts();
    let row = ChallengeRow {
        challenge_id: 0,
        kind: ChallengeKind::BatchRoot,
        batch_index,
        commitment: None,
        status: ChallengeStatus::Received,
        deadline,
        sp1_request_id: None,
        sp1_proof_bytes: None,
        tx_hash: None,
        nonce: None,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        l1_block: None,
        committed_at: now,
        last_status_change_at: now,
        last_polled_at: None,
    };
    db::insert_challenge(db_tx, row).await
}

pub(crate) async fn observe_resolved(
    db: &Arc<std::sync::Mutex<Db>>,
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    kind: ChallengeKind,
    batch_index: u64,
    commitment: Option<B256>,
) -> eyre::Result<()> {
    let row = {
        let guard = db.lock().unwrap_or_else(|e| e.into_inner());
        guard.find_challenge_by_event(kind, batch_index, commitment)
    };
    let Some(row) = row else { return Ok(()) };
    if row.status == ChallengeStatus::Resolved {
        return Ok(());
    }
    db::record_challenge_resolved(db_tx, row.challenge_id).await
}

/// Read `getBatch(batchIndex)` from L1, retrying with exponential backoff
/// until success or shutdown. Mirrors the listener's policy of "block on
/// L1 outage rather than advance past unobserved state".
async fn get_batch_with_retry(
    l1_provider: &impl Provider,
    contract_addr: Address,
    batch_index: u64,
    shutdown: &CancellationToken,
) -> eyre::Result<BatchOnChain> {
    let mut backoff = Duration::from_secs(1);
    loop {
        match l1_rollup_client::get_batch_on_chain(l1_provider, contract_addr, batch_index).await {
            Ok(b) => return Ok(b),
            Err(e) => {
                warn!(
                    batch_index,
                    err = %e,
                    backoff_secs = backoff.as_secs(),
                    "getBatch failed during challenge persist — retrying"
                );
                tokio::select! {
                    _ = shutdown.cancelled() => {
                        return Err(eyre::eyre!(
                            "shutdown during getBatch retry for batch {batch_index}"
                        ));
                    }
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(Duration::from_secs(60));
            }
        }
    }
}
