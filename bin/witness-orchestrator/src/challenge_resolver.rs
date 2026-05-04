//! Persistent challenge resolver: two parallel workers (one per kind)
//! drive challenge rows through the DB-backed status machine.
//!
//! - **Block-level** challenges: `received → sp1_proving → sp1_proved → dispatched → resolved`.
//!   Delegates SP1 Groth16 proof generation to the proxy `/challenge/sp1/{request,status}` API;
//!   before broadcasting the result, asserts the proxy's reported `vk_hash` matches the on-chain
//!   `programVKey()` cached at startup. Builds a merkle inclusion proof from L2 RPC data and
//!   submits `resolveBlockChallenge`.
//! - **Batch-root** challenges: `received → dispatched → resolved`. Reconstructs the merkle root
//!   locally from L2 RPC headers + receipts (no SP1) and submits `resolveBatchRootChallenge`.
//!
//! Workers do NOT share state beyond the SQLite handle and the
//! `NonceAllocator`. A long-running SP1 proof on the Block-worker
//! cannot starve a queued BatchRoot challenge.
//!
//! Each worker orders by deadline ASC so a tight-deadline challenge
//! takes precedence over a loose-deadline one — which `committed_at`
//! ordering would not respect after backfill.
//!
//! Pre-broadcast safety: every resolve template runs through
//! `validate_resolve_pre_broadcast` (cheap local merkle/chain assertions
//! plus an `eth_call` simulation against the contract). On any failure
//! the row is marked `Failed` and we do NOT broadcast — there is no
//! recovery by retry from the same inputs.

use std::{sync::Arc, time::Duration};

use alloy_primitives::{Bytes, FixedBytes, B256, U256};
use alloy_provider::Provider;
use alloy_rpc_types::{TransactionReceipt, TransactionRequest};
use fluent_stf_primitives::{
    BRIDGE_ADDRESS, BRIDGE_DEPOSIT_TOPIC, BRIDGE_ROLLBACK_TOPIC, BRIDGE_WITHDRAWAL_TOPIC,
    LEGACY_BRIDGE_WITHDRAWAL_TOPIC,
};
use l1_rollup_client::{
    prepare_resolve_batch_root_challenge_tx, prepare_resolve_block_challenge_tx, L2BlockHeader,
    MerkleProof, RollupTxPartial,
};
use nitro_types::ChallengeSp1Request;
use rsp_host_executor::events_hash::{
    calculate_deposit_hash, calculate_withdrawal_root, count_deposits,
};
use serde::{Deserialize, Serialize};
use tokio::time::MissedTickBehavior;
use tracing::{error, info, warn};

use crate::{
    db::{db_send_sync, ChallengeKind, ChallengePatch, ChallengeRow, ChallengeStatus, SyncOp},
    orchestrator::{DispatchBackoff, OrchestratorShared, RevertKind, STUCK_AT_CAP_TIMEOUT},
    rbf::{run_generic, RbfObserver},
};

/// Polling interval for `/challenge/sp1/status`.
const SP1_STATUS_POLL_INTERVAL: Duration = Duration::from_secs(15);

/// Active worker tick.
const WORKER_TICK: Duration = Duration::from_secs(1);

/// Average L1 block time used to translate `(deadline - current_block)` into wall-clock seconds.
const L1_BLOCK_SECS: u64 = 12;

// ============================================================================
// Worker entry point — two parallel workers, one per kind
// ============================================================================

pub(crate) async fn run(shared: Arc<OrchestratorShared>) {
    info!("challenge_resolver started (block + batch_root workers)");
    let block = {
        let shared = Arc::clone(&shared);
        tokio::spawn(async move { run_block_worker(shared).await })
    };
    let batch_root = {
        let shared = Arc::clone(&shared);
        tokio::spawn(async move { run_batch_root_worker(shared).await })
    };
    let _ = tokio::join!(block, batch_root);
    info!("challenge_resolver exiting");
}

async fn run_block_worker(shared: Arc<OrchestratorShared>) {
    let mut tick = tokio::time::interval(WORKER_TICK);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    tick.tick().await;
    let mut backoff = DispatchBackoff::default();

    loop {
        if shared.shutdown.is_cancelled() {
            break;
        }

        'work: {
            let row = {
                let guard = shared.db.lock().unwrap_or_else(|e| e.into_inner());
                guard.find_active_block_challenge()
            };
            let Some(row) = row else { break 'work };

            if check_and_fail_if_deadline_expired(&shared, &row).await {
                break 'work;
            }

            match row.status {
                ChallengeStatus::Received => {
                    handle_block_received(&shared, &row, &mut backoff).await
                }
                ChallengeStatus::Sp1Proving => handle_sp1_proving(&shared, &row).await,
                ChallengeStatus::Sp1Proved => handle_sp1_proved(&shared, &row, &mut backoff).await,
                ChallengeStatus::Dispatched => {
                    handle_dispatched_resume(&shared, &row, &mut backoff).await;
                }
                ChallengeStatus::Resolved | ChallengeStatus::Failed => {
                    warn!(
                        challenge_id = row.challenge_id,
                        status = ?row.status,
                        "block worker active gate returned terminal row"
                    );
                }
            }
        }

        tokio::select! {
            biased;
            _ = shared.shutdown.cancelled() => break,
            _ = tick.tick() => {}
        }
    }
    info!("block_worker exiting");
}

async fn run_batch_root_worker(shared: Arc<OrchestratorShared>) {
    let mut tick = tokio::time::interval(WORKER_TICK);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    tick.tick().await;
    let mut backoff = DispatchBackoff::default();

    loop {
        if shared.shutdown.is_cancelled() {
            break;
        }

        'work: {
            let row = {
                let guard = shared.db.lock().unwrap_or_else(|e| e.into_inner());
                guard.find_active_batch_root_challenge()
            };
            let Some(row) = row else { break 'work };

            if check_and_fail_if_deadline_expired(&shared, &row).await {
                break 'work;
            }

            match row.status {
                ChallengeStatus::Received => {
                    run_resolve_lifecycle(&shared, &row, &mut backoff).await;
                }
                ChallengeStatus::Dispatched => {
                    handle_dispatched_resume(&shared, &row, &mut backoff).await;
                }
                other => {
                    warn!(
                        challenge_id = row.challenge_id,
                        status = ?other,
                        "batch_root worker active gate returned unexpected row"
                    );
                }
            }
        }

        tokio::select! {
            biased;
            _ = shared.shutdown.cancelled() => break,
            _ = tick.tick() => {}
        }
    }
    info!("batch_root_worker exiting");
}

// ============================================================================
// Deadline gate
// ============================================================================

/// Returns `true` if the row was past its resolution deadline and was
/// transitioned to `Failed`. Operator must call `revertBatches` on L1.
async fn check_and_fail_if_deadline_expired(
    shared: &OrchestratorShared,
    row: &ChallengeRow,
) -> bool {
    let Ok(current_l1_block) = shared.config.l1_provider.get_block_number().await else {
        return false;
    };
    if current_l1_block <= row.deadline {
        return false;
    }
    metrics::counter!(
        "orchestrator_challenge_deadline_expired_total",
        "kind" => row.kind.as_str(),
    )
    .increment(1);
    error!(
        challenge_id = row.challenge_id,
        kind = row.kind.as_str(),
        deadline = row.deadline,
        current_l1_block,
        "challenge deadline expired — marking failed (rollup will go corrupted; \
         operator must call revertBatches)"
    );
    let patch = ChallengePatch { status: Some(ChallengeStatus::Failed), ..Default::default() };
    persist_patch(shared, row.challenge_id, patch).await;
    true
}

// ============================================================================
// Block-kind status handlers
// ============================================================================

async fn handle_block_received(
    shared: &OrchestratorShared,
    row: &ChallengeRow,
    _backoff: &mut DispatchBackoff,
) {
    let target_block_number = match resolve_block_target(shared, row).await {
        Some(n) => n,
        None => return,
    };
    let (from_block, to_block) = match lookup_batch_range(shared, row.batch_index) {
        Ok(r) => r,
        Err(e) => {
            warn!(challenge_id = row.challenge_id, err = %e, "lookup_batch_range failed");
            return;
        }
    };

    // 1. Get bincode-serialized EthClientExecutorInput from the driver. Cold-store hit is verbatim;
    //    cold miss falls through to an MDBX-backed rebuild.
    let witness_bytes = match shared.driver.get_or_build_witness(target_block_number).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            warn!(
                challenge_id = row.challenge_id,
                target_block_number, "witness not available (block beyond MDBX tip or zero)"
            );
            return;
        }
        Err(e) => {
            warn!(
                challenge_id = row.challenge_id,
                target_block_number,
                err = %e,
                "Driver::get_or_build_witness failed"
            );
            return;
        }
    };
    let client_input: rsp_client_executor::io::EthClientExecutorInput =
        match bincode::deserialize(&witness_bytes) {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    challenge_id = row.challenge_id,
                    target_block_number,
                    err = %e,
                    "deserialize EthClientExecutorInput from witness payload failed"
                );
                return;
            }
        };

    // 2. Build canonical EIP-4844 blobs from L2 transaction data.
    let blobs = match rsp_blob_builder::build_blobs_from_l2(
        &shared.config.l2_provider,
        from_block,
        to_block,
    )
    .await
    {
        Ok(b) => b,
        Err(e) => {
            warn!(
                challenge_id = row.challenge_id,
                from_block,
                to_block,
                err = %e,
                "build_blobs_from_l2 failed"
            );
            return;
        }
    };

    // 3. Wrap and POST to the proxy.
    let payload = ChallengeSp1Request { client_input: Box::new(client_input), blobs };
    match post_sp1_request(
        &shared.config.http_client,
        &shared.config.proxy_url,
        &shared.config.api_key,
        &payload,
    )
    .await
    {
        Ok(request_id) => {
            let patch = ChallengePatch {
                status: Some(ChallengeStatus::Sp1Proving),
                sp1_request_id: Some(Some(request_id)),
                ..Default::default()
            };
            persist_patch(shared, row.challenge_id, patch).await;
            info!(
                challenge_id = row.challenge_id,
                batch_index = row.batch_index,
                target_block_number,
                num_blobs = payload.blobs.len(),
                %request_id,
                "SP1 proof requested via proxy"
            );
        }
        Err(e) => {
            warn!(
                challenge_id = row.challenge_id,
                err = %e,
                "post_sp1_request failed"
            );
        }
    }
}

async fn handle_sp1_proving(shared: &OrchestratorShared, row: &ChallengeRow) {
    // CHECK constraint guarantees Sp1Proving rows always carry sp1_request_id.
    // This `else` is defensive only — real divergence would mean DB corruption.
    let Some(request_id) = row.sp1_request_id else {
        error!(
            challenge_id = row.challenge_id,
            "BUG: Sp1Proving row without sp1_request_id (CHECK constraint violated)"
        );
        return;
    };
    match poll_sp1_status(
        &shared.config.http_client,
        &shared.config.proxy_url,
        &shared.config.api_key,
        request_id,
    )
    .await
    {
        Ok(Sp1StatusOutcome::Ready { vk_hash, proof_bytes }) => {
            let on_chain = shared.config.on_chain_program_vkey;
            if vk_hash != on_chain {
                error!(
                    challenge_id = row.challenge_id,
                    proxy_vk_hash = %vk_hash,
                    on_chain_vk_hash = %shared.config.on_chain_program_vkey,
                    "vk_hash mismatch — proxy SP1 ELF diverged from on-chain programVKey; \
                     marking challenge failed (proxy redeploy required)"
                );
                let patch =
                    ChallengePatch { status: Some(ChallengeStatus::Failed), ..Default::default() };
                persist_patch(shared, row.challenge_id, patch).await;
                return;
            }
            let patch = ChallengePatch {
                status: Some(ChallengeStatus::Sp1Proved),
                sp1_proof_bytes: Some(Some(proof_bytes)),
                ..Default::default()
            };
            persist_patch(shared, row.challenge_id, patch).await;
            info!(challenge_id = row.challenge_id, "SP1 proof ready");
        }
        Ok(Sp1StatusOutcome::Pending) => {}
        Err(Sp1StatusError::Lost) => {
            metrics::counter!(
                "orchestrator_challenge_sp1_request_lost_total",
                "kind" => row.kind.as_str(),
            )
            .increment(1);
            warn!(
                challenge_id = row.challenge_id,
                %request_id,
                "SP1 request lost (proxy 404) — clearing request_id and re-issuing"
            );
            let patch = ChallengePatch {
                status: Some(ChallengeStatus::Received),
                sp1_request_id: Some(None),
                ..Default::default()
            };
            persist_patch(shared, row.challenge_id, patch).await;
        }
        Err(Sp1StatusError::Other(e)) => {
            warn!(
                challenge_id = row.challenge_id,
                err = %e,
                "poll_sp1_status failed — retrying next tick"
            );
        }
    }
}

async fn handle_sp1_proved(
    shared: &OrchestratorShared,
    row: &ChallengeRow,
    backoff: &mut DispatchBackoff,
) {
    run_resolve_lifecycle(shared, row, backoff).await;
}

async fn handle_dispatched_resume(
    shared: &OrchestratorShared,
    row: &ChallengeRow,
    backoff: &mut DispatchBackoff,
) {
    let Some(nonce) = row.nonce else {
        // `Dispatched + nonce=NULL` is an invariant violation: a row in
        // Dispatched was either entered via `on_first_broadcast` (which
        // writes nonce) or via cross-process resume (which preserves
        // nonce). Failure paths (`on_reverted`, `on_pre_receipt_failure`)
        // roll the row back out of Dispatched to the per-kind fresh-
        // dispatch entry point. Reaching this branch implies DB
        // corruption or a regression of that rollback contract.
        error!(
            challenge_id = row.challenge_id,
            kind = row.kind.as_str(),
            "BUG: Dispatched challenge row without persisted nonce — skipping resume"
        );
        return;
    };

    let partial = match prepare_resolve_partial(shared, row).await {
        Ok(p) => p,
        Err(e) => {
            warn!(
                challenge_id = row.challenge_id,
                err = %e,
                "prepare_resolve_partial (resume) failed"
            );
            return;
        }
    };

    if let Err(reason) = validate_resolve_pre_broadcast(shared, row, &partial).await {
        fail_with_reason(shared, row, reason).await;
        return;
    }

    let resume = match (row.tx_hash, row.max_fee_per_gas, row.max_priority_fee_per_gas) {
        (Some(h), Some(fee), Some(tip)) => Some(crate::db::RbfResumeState {
            nonce,
            tx_hash: h,
            max_fee_per_gas: fee,
            max_priority_fee_per_gas: tip,
        }),
        _ => None,
    };

    let (fee, tip) = match resume.as_ref() {
        Some(r) => (r.max_fee_per_gas, r.max_priority_fee_per_gas),
        None => match estimate_initial_fees(shared, row).await {
            Some(v) => v,
            None => return,
        },
    };

    let template = partial.with_nonce(nonce);
    let observer = ResolveObserver {
        shared,
        challenge_id: row.challenge_id,
        kind: row.kind,
        nonce,
        batch_index: row.batch_index,
    };
    let budget = compute_wall_clock_budget(&shared.config.l1_provider, row.deadline).await;
    run_generic(
        shared,
        row.batch_index,
        &template,
        nonce,
        resume,
        fee,
        tip,
        budget,
        &observer,
        backoff,
    )
    .await;
}

/// Build the calldata, run pre-broadcast validation, estimate fees, allocate
/// the nonce only after every RPC-revert-prone step succeeded, then enter
/// the RBF lifecycle. Used by both kinds for the initial dispatch from
/// `Received` (BatchRoot) or `Sp1Proved` (Block).
///
/// The defer-allocate ordering is the load-bearing invariant: a permission
/// revert during prepare (e.g. `AccessControlUnauthorizedAccount`) must NOT
/// burn a nonce, because tail-CAS `release` cannot rewind past concurrent
/// allocations from other workers.
async fn run_resolve_lifecycle(
    shared: &OrchestratorShared,
    row: &ChallengeRow,
    backoff: &mut DispatchBackoff,
) {
    let partial = match prepare_resolve_partial(shared, row).await {
        Ok(p) => p,
        Err(e) => {
            warn!(
                challenge_id = row.challenge_id,
                err = %e,
                "prepare_resolve_partial failed"
            );
            return;
        }
    };

    if let Err(reason) = validate_resolve_pre_broadcast(shared, row, &partial).await {
        fail_with_reason(shared, row, reason).await;
        return;
    }

    let (fee, tip) = match estimate_initial_fees(shared, row).await {
        Some(v) => v,
        None => return,
    };

    let nonce = shared.nonce_allocator.allocate();
    crate::metrics::set_nonce_allocator_next(shared.nonce_allocator.peek());

    let template = partial.with_nonce(nonce);
    let observer = ResolveObserver {
        shared,
        challenge_id: row.challenge_id,
        kind: row.kind,
        nonce,
        batch_index: row.batch_index,
    };
    let budget = compute_wall_clock_budget(&shared.config.l1_provider, row.deadline).await;
    run_generic(
        shared,
        row.batch_index,
        &template,
        nonce,
        None,
        fee,
        tip,
        budget,
        &observer,
        backoff,
    )
    .await;
}

async fn estimate_initial_fees(
    shared: &OrchestratorShared,
    row: &ChallengeRow,
) -> Option<(u128, u128)> {
    let cap = shared.config.rbf_max_fee_per_gas_wei;
    let est = match shared.config.l1_provider.estimate_eip1559_fees().await {
        Ok(e) => e,
        Err(e) => {
            warn!(
                challenge_id = row.challenge_id,
                err = %e,
                "estimate_eip1559_fees failed"
            );
            return None;
        }
    };
    let mut fee = est.max_fee_per_gas;
    let mut tip = est.max_priority_fee_per_gas;
    if fee >= cap {
        fee = cap;
        if tip > cap {
            tip = cap;
        }
        warn!(
            challenge_id = row.challenge_id,
            kind = row.kind.as_str(),
            max_fee_cap = cap,
            "resolve initial fee at/above cap"
        );
    }
    Some((fee, tip))
}

/// Compute the per-resolve wall-clock budget for the RBF stuck-at-cap
/// timeout: the smaller of the preconfirm-tuned default and
/// `(deadline - current_block) × ~12s`. Caps at the static default so a
/// huge deadline doesn't extend the budget unnecessarily.
async fn compute_wall_clock_budget(l1_provider: &impl Provider, deadline: u64) -> Duration {
    let current = l1_provider.get_block_number().await.unwrap_or(0);
    let blocks_left = deadline.saturating_sub(current);
    let computed = Duration::from_secs(blocks_left.saturating_mul(L1_BLOCK_SECS));
    std::cmp::min(STUCK_AT_CAP_TIMEOUT, computed)
}

async fn fail_with_reason(shared: &OrchestratorShared, row: &ChallengeRow, reason: String) {
    error!(
        challenge_id = row.challenge_id,
        kind = row.kind.as_str(),
        reason = %reason,
        "pre-broadcast validation failed — marking challenge failed"
    );
    metrics::counter!(
        "orchestrator_challenge_pre_broadcast_failed_total",
        "kind" => row.kind.as_str(),
    )
    .increment(1);
    let patch = ChallengePatch { status: Some(ChallengeStatus::Failed), ..Default::default() };
    persist_patch(shared, row.challenge_id, patch).await;
}

// ============================================================================
// Pre-broadcast validation: local cheap checks + eth_call simulation
// ============================================================================

/// Catch-all defense before broadcasting a resolve tx: simulate the
/// signed calldata via `eth_call`. If the contract would revert, we
/// surface the revert reason and abort — there is no recovery from the
/// same inputs, retry is wasted gas.
///
/// Local merkle / chain-linkage assertions are NOT duplicated here
/// because they are already implicit in `prepare_resolve_partial` (which
/// produces calldata derived from the same headers/leaves the contract
/// re-validates). The simulation is the catch-all; it covers any future
/// contract revert path automatically.
async fn validate_resolve_pre_broadcast(
    shared: &OrchestratorShared,
    row: &ChallengeRow,
    partial: &RollupTxPartial,
) -> Result<(), String> {
    let req = TransactionRequest {
        from: Some(shared.config.l1_signer_address),
        to: Some(partial.to.into()),
        input: partial.input.clone().into(),
        ..Default::default()
    };
    match shared.config.l1_provider.call(req).await {
        Ok(_) => Ok(()),
        Err(e) => Err(format!(
            "eth_call simulation reverted (challenge_id={}, kind={}): {e}",
            row.challenge_id,
            row.kind.as_str()
        )),
    }
}

// ============================================================================
// Resolve template construction
// ============================================================================

/// Per-kind dispatcher: builds either a `resolveBlockChallenge` or a
/// `resolveBatchRootChallenge` envelope without a nonce. Caller attaches
/// the allocated nonce via `RollupTxPartial::with_nonce` just before
/// broadcast.
async fn prepare_resolve_partial(
    shared: &OrchestratorShared,
    row: &ChallengeRow,
) -> eyre::Result<RollupTxPartial> {
    match row.kind {
        ChallengeKind::Block => prepare_block_resolve_partial(shared, row).await,
        ChallengeKind::BatchRoot => prepare_batch_root_resolve_partial(shared, row).await,
    }
}

async fn prepare_block_resolve_partial(
    shared: &OrchestratorShared,
    row: &ChallengeRow,
) -> eyre::Result<RollupTxPartial> {
    let cfg = &shared.config;
    let commitment =
        row.commitment.ok_or_else(|| eyre::eyre!("block challenge row missing commitment"))?;
    let sp1_proof = row
        .sp1_proof_bytes
        .clone()
        .ok_or_else(|| eyre::eyre!("block challenge row missing sp1_proof_bytes"))?;

    let (from_block, to_block) = lookup_batch_range(shared, row.batch_index)?;

    let (headers, leaves, target_idx) =
        collect_headers_with_target(&cfg.l2_provider, from_block, to_block, Some(commitment))
            .await
            .ok_or_else(|| eyre::eyre!("collect_headers_with_target failed"))?;

    let idx = target_idx.ok_or_else(|| {
        eyre::eyre!("no matching leaf in batch {} for commitment {commitment}", row.batch_index)
    })?;

    let (proof_nonce, proof_bytes) = batch_merkle::build_merkle_proof(&leaves, idx);
    let merkle_proof =
        MerkleProof { nonce: U256::from(proof_nonce), proof: Bytes::from(proof_bytes) };

    prepare_resolve_block_challenge_tx(
        &cfg.l1_provider,
        cfg.l1_rollup_addr,
        row.batch_index,
        headers[idx].clone(),
        merkle_proof,
        sp1_proof,
        cfg.l1_signer_address,
    )
    .await
}

async fn prepare_batch_root_resolve_partial(
    shared: &OrchestratorShared,
    row: &ChallengeRow,
) -> eyre::Result<RollupTxPartial> {
    let cfg = &shared.config;
    if row.batch_index == 0 {
        return Err(eyre::eyre!("batch 0 is genesis — cannot resolve batch-root challenge"));
    }

    let (from_block, to_block) = lookup_batch_range(shared, row.batch_index)?;
    let (prev_from, prev_to) = lookup_batch_range(shared, row.batch_index - 1)?;

    let (headers, _leaves, _) =
        collect_headers_with_target(&cfg.l2_provider, from_block, to_block, None)
            .await
            .ok_or_else(|| eyre::eyre!("collect_headers_with_target (current) failed"))?;
    let (prev_headers, prev_leaves, _) =
        collect_headers_with_target(&cfg.l2_provider, prev_from, prev_to, None)
            .await
            .ok_or_else(|| eyre::eyre!("collect_headers_with_target (previous) failed"))?;

    let prev_last_idx = prev_headers.len() - 1;
    let last_block_header_in_previous_batch = prev_headers[prev_last_idx].clone();
    let (proof_nonce, proof_bytes) = batch_merkle::build_merkle_proof(&prev_leaves, prev_last_idx);
    let last_block_proof =
        MerkleProof { nonce: U256::from(proof_nonce), proof: Bytes::from(proof_bytes) };

    prepare_resolve_batch_root_challenge_tx(
        &cfg.l1_provider,
        cfg.l1_rollup_addr,
        row.batch_index,
        last_block_header_in_previous_batch,
        headers,
        last_block_proof,
        cfg.l1_signer_address,
    )
    .await
}

/// Local lookup of `(from_block, to_block)` for a batch. The orchestrator
/// observes every `BatchCommitted` event via the listener, so the row
/// must be present in the local DB by the time any challenge for it is
/// processed. A missing row is a fatal invariant violation.
fn lookup_batch_range(shared: &OrchestratorShared, batch_index: u64) -> eyre::Result<(u64, u64)> {
    let guard = shared.db.lock().unwrap_or_else(|e| e.into_inner());
    guard.find_batch(batch_index).map(|b| (b.from_block, b.to_block)).ok_or_else(|| {
        eyre::eyre!(
            "batch {batch_index} not found in local DB — invariant violation: \
                 orchestrator must observe every BatchCommitted before any challenge for it"
        )
    })
}

/// Resolve the L2 block number that backs the disputed commitment by
/// scanning the batch's blocks. Returns `None` on RPC failure or absent
/// match (caller logs and waits for the next tick).
async fn resolve_block_target(shared: &OrchestratorShared, row: &ChallengeRow) -> Option<u64> {
    let cfg = &shared.config;
    let commitment = match row.commitment {
        Some(c) => c,
        None => {
            warn!(challenge_id = row.challenge_id, "block challenge row missing commitment");
            return None;
        }
    };
    let (from_block, to_block) = match lookup_batch_range(shared, row.batch_index) {
        Ok(r) => r,
        Err(e) => {
            warn!(
                challenge_id = row.challenge_id,
                err = %e,
                "lookup_batch_range failed"
            );
            return None;
        }
    };
    let (_, _leaves, target_idx) =
        collect_headers_with_target(&cfg.l2_provider, from_block, to_block, Some(commitment))
            .await?;
    let idx = target_idx?;
    Some(from_block + idx as u64)
}

async fn persist_patch(shared: &OrchestratorShared, challenge_id: i64, patch: ChallengePatch) {
    if let Err(e) =
        db_send_sync(&shared.db_tx, SyncOp::PatchChallenge { challenge_id, patch }).await
    {
        tracing::error!(challenge_id, err = %e, "persist_patch (challenge) failed");
    }
}

/// Status to roll back to when a dispatched challenge tx fails (revert
/// receipt, stuck-at-cap timeout). The rollback target is the fresh-
/// dispatch entry point in the per-kind worker so `run_resolve_lifecycle`
/// re-runs the full defer-allocate cycle on the next tick.
fn rollback_status_for(kind: ChallengeKind) -> ChallengeStatus {
    match kind {
        ChallengeKind::Block => ChallengeStatus::Sp1Proved,
        ChallengeKind::BatchRoot => ChallengeStatus::Received,
    }
}

// ============================================================================
// Header construction (RPC + receipts → L2BlockHeader)
// ============================================================================

/// Walk `[from_block, to_block]`, build an `L2BlockHeader` per block from
/// L2 RPC, and compute the merkle leaf. If `target_commitment` is set,
/// returns the index of the matching leaf.
async fn collect_headers_with_target(
    l2_provider: &alloy_provider::RootProvider,
    from_block: u64,
    to_block: u64,
    target_commitment: Option<B256>,
) -> Option<(Vec<L2BlockHeader>, Vec<B256>, Option<usize>)> {
    let count = (to_block - from_block + 1) as usize;
    let mut headers: Vec<L2BlockHeader> = Vec::with_capacity(count);
    let mut leaves: Vec<B256> = Vec::with_capacity(count);
    let mut target_idx: Option<usize> = None;
    for (i, block_number) in (from_block..=to_block).enumerate() {
        let header = match build_l2_block_header(l2_provider, block_number).await {
            Ok(h) => h,
            Err(e) => {
                warn!(block_number, err = %e, "failed to build L2BlockHeader");
                return None;
            }
        };
        let leaf = batch_merkle::compute_leaf(
            header.previousBlockHash,
            header.blockHash,
            header.withdrawalRoot,
            header.depositRoot,
        );
        if let Some(c) = target_commitment {
            if leaf == c {
                target_idx = Some(i);
            }
        }
        headers.push(header);
        leaves.push(leaf);
    }
    Some((headers, leaves, target_idx))
}

async fn build_l2_block_header(
    l2_provider: &alloy_provider::RootProvider,
    block_number: u64,
) -> eyre::Result<L2BlockHeader> {
    let block = l2_provider
        .get_block_by_number(block_number.into())
        .await
        .map_err(|e| eyre::eyre!("get_block_by_number({block_number}) failed: {e}"))?
        .ok_or_else(|| eyre::eyre!("block {block_number} not found on L2"))?;

    let receipts: Vec<TransactionReceipt> = l2_provider
        .get_block_receipts(block_number.into())
        .await
        .map_err(|e| eyre::eyre!("get_block_receipts({block_number}) failed: {e}"))?
        .unwrap_or_default();

    let withdrawal_root = calculate_withdrawal_root(
        &receipts,
        BRIDGE_ADDRESS,
        BRIDGE_WITHDRAWAL_TOPIC,
        LEGACY_BRIDGE_WITHDRAWAL_TOPIC,
        BRIDGE_ROLLBACK_TOPIC,
    );
    let deposit_root = calculate_deposit_hash(&receipts, BRIDGE_ADDRESS, BRIDGE_DEPOSIT_TOPIC);
    let deposit_count = count_deposits(&receipts, BRIDGE_ADDRESS, BRIDGE_DEPOSIT_TOPIC);

    Ok(L2BlockHeader {
        previousBlockHash: block.header.parent_hash,
        blockHash: block.header.hash,
        withdrawalRoot: withdrawal_root,
        depositRoot: deposit_root,
        depositCount: deposit_count,
    })
}

// ============================================================================
// Proxy SP1 round-trip
// ============================================================================

/// zstd level used to compress the bincode-serialized
/// [`ChallengeSp1Request`] body. Same level as
/// `/sign-block-execution` (the only other heavy POST path).
#[cfg(feature = "zstd-block-payload")]
const ZSTD_COMPRESSION_LEVEL: i32 = 3;

#[derive(Serialize)]
struct Sp1StatusBody {
    request_id: B256,
}

#[derive(Deserialize)]
struct Sp1RequestResponse {
    request_id: B256,
}

#[derive(Deserialize)]
struct Sp1ProofResponse {
    vk_hash: FixedBytes<32>,
    /// The contract reconstructs publicValues from the block header +
    /// blob hashes; we don't forward this field to L1. Kept for symmetry
    /// with the proxy schema and operator inspection.
    #[allow(dead_code)]
    public_values: Vec<u8>,
    proof_bytes: Vec<u8>,
}

enum Sp1StatusOutcome {
    Ready { vk_hash: FixedBytes<32>, proof_bytes: Vec<u8> },
    Pending,
}

enum Sp1StatusError {
    /// Proxy returned 404 — the request was lost (e.g. proxy DB wipe).
    /// Caller re-issues by clearing `sp1_request_id`.
    Lost,
    Other(eyre::Report),
}

async fn post_sp1_request(
    http_client: &reqwest::Client,
    proxy_url: &str,
    api_key: &str,
    payload: &ChallengeSp1Request,
) -> eyre::Result<B256> {
    let serialized = bincode::serialize(payload)
        .map_err(|e| eyre::eyre!("bincode serialize ChallengeSp1Request: {e}"))?;

    #[cfg(feature = "zstd-block-payload")]
    let (body, content_encoding): (Vec<u8>, Option<&'static str>) = {
        let uncompressed_len = serialized.len();
        let compressed = zstd::encode_all(serialized.as_slice(), ZSTD_COMPRESSION_LEVEL)
            .map_err(|e| eyre::eyre!("zstd encode ChallengeSp1Request: {e}"))?;
        tracing::debug!(
            uncompressed_len,
            compressed_len = compressed.len(),
            "Compressed ChallengeSp1Request payload"
        );
        (compressed, Some("zstd"))
    };
    #[cfg(not(feature = "zstd-block-payload"))]
    let (body, content_encoding): (Vec<u8>, Option<&'static str>) = (serialized, None);

    let mut req = http_client
        .post(format!("{proxy_url}/challenge/sp1/request"))
        .header("x-api-key", api_key)
        .header("content-type", "application/octet-stream")
        .body(body);
    if let Some(enc) = content_encoding {
        req = req.header("content-encoding", enc);
    }
    let resp =
        req.send().await.map_err(|e| eyre::eyre!("/challenge/sp1/request POST failed: {e}"))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(eyre::eyre!("/challenge/sp1/request returned {status}: {body}"));
    }
    let body: Sp1RequestResponse =
        resp.json().await.map_err(|e| eyre::eyre!("decode /challenge/sp1/request body: {e}"))?;
    Ok(body.request_id)
}

async fn poll_sp1_status(
    http_client: &reqwest::Client,
    proxy_url: &str,
    api_key: &str,
    request_id: B256,
) -> Result<Sp1StatusOutcome, Sp1StatusError> {
    // Pace successive polls inside a single tick. The active worker re-enters
    // this function on its 1s tick; this short sleep prevents the unlikely
    // case of double-polling from back-to-back ticks.
    tokio::time::sleep(SP1_STATUS_POLL_INTERVAL).await;

    let resp = http_client
        .post(format!("{proxy_url}/challenge/sp1/status"))
        .header("x-api-key", api_key)
        .json(&Sp1StatusBody { request_id })
        .send()
        .await
        .map_err(|e| {
            Sp1StatusError::Other(eyre::eyre!("/challenge/sp1/status POST failed: {e}"))
        })?;

    match resp.status().as_u16() {
        200 => {
            let proof: Sp1ProofResponse = resp
                .json()
                .await
                .map_err(|e| Sp1StatusError::Other(eyre::eyre!("decode proof body: {e}")))?;
            Ok(Sp1StatusOutcome::Ready { vk_hash: proof.vk_hash, proof_bytes: proof.proof_bytes })
        }
        202 => Ok(Sp1StatusOutcome::Pending),
        404 => Err(Sp1StatusError::Lost),
        other => {
            let body = resp.text().await.unwrap_or_default();
            Err(Sp1StatusError::Other(eyre::eyre!(
                "/challenge/sp1/status returned {other}: {body}"
            )))
        }
    }
}

// ============================================================================
// Stateful RbfObserver — mirrors PreconfirmObserver
// ============================================================================

pub(crate) struct ResolveObserver<'a> {
    shared: &'a OrchestratorShared,
    challenge_id: i64,
    kind: ChallengeKind,
    nonce: u64,
    batch_index: u64,
}

#[async_trait::async_trait]
impl RbfObserver for ResolveObserver<'_> {
    async fn on_first_broadcast(&self, hash: B256, fee: u128, tip: u128) {
        info!(
            kind = self.kind.as_str(),
            challenge_id = self.challenge_id,
            batch_index = self.batch_index,
            %hash,
            max_fee_per_gas = fee,
            max_priority_fee_per_gas = tip,
            "resolve broadcast (initial)"
        );
        let patch = ChallengePatch {
            status: Some(ChallengeStatus::Dispatched),
            tx_hash: Some(Some(hash)),
            nonce: Some(Some(self.nonce)),
            max_fee_per_gas: Some(Some(fee)),
            max_priority_fee_per_gas: Some(Some(tip)),
            ..Default::default()
        };
        persist_patch(self.shared, self.challenge_id, patch).await;
        crate::metrics::counter_resolve_dispatched(self.kind.as_str());
    }

    async fn on_rebroadcast(&self, hash: B256, fee: u128, tip: u128) {
        info!(
            kind = self.kind.as_str(),
            challenge_id = self.challenge_id,
            batch_index = self.batch_index,
            %hash,
            max_fee_per_gas = fee,
            max_priority_fee_per_gas = tip,
            "resolve RBF rebroadcast"
        );
        let patch = ChallengePatch {
            tx_hash: Some(Some(hash)),
            max_fee_per_gas: Some(Some(fee)),
            max_priority_fee_per_gas: Some(Some(tip)),
            ..Default::default()
        };
        persist_patch(self.shared, self.challenge_id, patch).await;
    }

    async fn on_submitted(&self, hash: B256, l1_block: u64) {
        info!(
            kind = self.kind.as_str(),
            challenge_id = self.challenge_id,
            batch_index = self.batch_index,
            %hash,
            l1_block,
            "resolve confirmed on L1"
        );
        let patch = ChallengePatch { l1_block: Some(Some(l1_block)), ..Default::default() };
        persist_patch(self.shared, self.challenge_id, patch).await;
        crate::metrics::counter_resolve_submitted(self.kind.as_str());
    }

    async fn on_reverted(&self, hash: B256, kind: RevertKind) {
        warn!(
            kind = self.kind.as_str(),
            challenge_id = self.challenge_id,
            batch_index = self.batch_index,
            %hash,
            ?kind,
            "resolve REVERTED on L1 — alert + retry"
        );
        crate::metrics::counter_resolve_rejected(self.kind.as_str());
        // Roll back to the fresh-dispatch entry point so the worker re-runs
        // the full defer-allocate cycle (prepare → validate → fees →
        // allocate) on its next tick. Block kind keeps `sp1_proof_bytes`
        // and resumes from `Sp1Proved` (skips the SP1 round-trip);
        // batch_root resumes from `Received` (no SP1 phase).
        let patch = ChallengePatch {
            status: Some(rollback_status_for(self.kind)),
            tx_hash: Some(None),
            nonce: Some(None),
            max_fee_per_gas: Some(None),
            max_priority_fee_per_gas: Some(None),
            ..Default::default()
        };
        persist_patch(self.shared, self.challenge_id, patch).await;
    }

    async fn on_pre_receipt_failure(&self, reason: &'static str) {
        warn!(
            kind = self.kind.as_str(),
            challenge_id = self.challenge_id,
            batch_index = self.batch_index,
            reason,
            "resolve pre-receipt failure — alert + retry"
        );
        crate::metrics::counter_resolve_pre_receipt_failure(self.kind.as_str());
        let patch = ChallengePatch {
            status: Some(rollback_status_for(self.kind)),
            tx_hash: Some(None),
            nonce: Some(None),
            max_fee_per_gas: Some(None),
            max_priority_fee_per_gas: Some(None),
            ..Default::default()
        };
        persist_patch(self.shared, self.challenge_id, patch).await;
    }

    async fn should_abort(&self) -> bool {
        let row = {
            let guard = self.shared.db.lock().unwrap_or_else(|e| e.into_inner());
            guard.find_challenge_by_id(self.challenge_id)
        };
        match row {
            Some(r) => matches!(r.status, ChallengeStatus::Resolved | ChallengeStatus::Failed),
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pure-Rust mirror of `MerkleTree.verifyMerkleProof` from the
    /// rollup contract. `nonce` is the leaf index; `proof` is a packed
    /// sequence of 32-byte sibling hashes from leaf to root.
    fn verify_merkle_proof(root: B256, leaf: B256, mut nonce: u64, proof: &[u8]) -> bool {
        if !proof.len().is_multiple_of(32) {
            return false;
        }
        let mut hash = leaf;
        for chunk in proof.chunks_exact(32) {
            let sibling = B256::from_slice(chunk);
            hash = if nonce.is_multiple_of(2) {
                batch_merkle::keccak_pair(hash, sibling)
            } else {
                batch_merkle::keccak_pair(sibling, hash)
            };
            nonce /= 2;
        }
        hash == root
    }

    /// End-to-end mirror of `Rollup.resolveBatchRootChallenge`'s
    /// validation against real Fluent testnet data for batch 877. Runs
    /// the four checks the contract performs that depend on real chain
    /// state.
    #[tokio::test]
    #[ignore = "requires INTEGRATION_L2_RPC_URL; hits real L2 RPC for ~2k blocks"]
    async fn real_batch_877_resolve_validation() {
        const BATCH_877_FROM: u64 = 25_448_823;
        const BATCH_877_TO: u64 = 25_449_846;
        const BATCH_877_ROOT: B256 = alloy_primitives::b256!(
            "0x385f55c1589c3cd05c0f9b2360870c5aa818384d2bfbb990491c6acc34a4c1c4"
        );

        const BATCH_876_FROM: u64 = 25_447_799;
        const BATCH_876_TO: u64 = 25_448_822;
        const BATCH_876_ROOT: B256 = alloy_primitives::b256!(
            "0x0631672b00a8e80b9750db0b89a32cd4eb58929fd9fb196666f1e637e5ac0020"
        );

        let rpc_url = std::env::var("INTEGRATION_L2_RPC_URL")
            .expect("INTEGRATION_L2_RPC_URL must be set to run this integration test");
        let url: url::Url = rpc_url.parse().expect("INTEGRATION_L2_RPC_URL is not a valid URL");
        let l2: alloy_provider::RootProvider =
            rsp_provider::create_provider(url).expect("failed to build L2 provider");

        let (headers_877, leaves_877, _) =
            collect_headers_with_target(&l2, BATCH_877_FROM, BATCH_877_TO, None)
                .await
                .expect("collect_headers_with_target(877) failed");
        assert_eq!(
            leaves_877.len() as u64,
            BATCH_877_TO - BATCH_877_FROM + 1,
            "batch 877 leaf count != range"
        );

        let local_root_877 = batch_merkle::calculate_merkle_root(&leaves_877);
        assert_eq!(local_root_877, BATCH_877_ROOT, "batch 877 local root != on-chain batchRoot");

        for i in 0..headers_877.len() - 1 {
            assert_eq!(
                headers_877[i].blockHash,
                headers_877[i + 1].previousBlockHash,
                "batch 877 chain break between local index {i} and {}",
                i + 1
            );
        }

        let (headers_876, leaves_876, _) =
            collect_headers_with_target(&l2, BATCH_876_FROM, BATCH_876_TO, None)
                .await
                .expect("collect_headers_with_target(876) failed");
        let last_idx_876 = leaves_876.len() - 1;
        let last_header_876 = &headers_876[last_idx_876];

        assert_eq!(
            last_header_876.blockHash, headers_877[0].previousBlockHash,
            "cross-batch chain break: last(876).blockHash != first(877).previousBlockHash"
        );

        let last_leaf_876 = leaves_876[last_idx_876];
        let (nonce, proof_bytes) = batch_merkle::build_merkle_proof(&leaves_876, last_idx_876);
        assert!(
            verify_merkle_proof(BATCH_876_ROOT, last_leaf_876, nonce, &proof_bytes),
            "merkle inclusion proof for last leaf of batch 876 failed against on-chain root"
        );

        println!(
            "✓ batch 877 resolve calldata validates: root={local_root_877}, chain linkage OK, cross-batch link OK, last-leaf-of-876 inclusion proof OK"
        );
    }
}
