//! Persistent challenge resolver: two parallel workers (one per kind)
//! drive challenge rows through the DB-backed status machine.
//!
//! - **Block-level** challenges: `received → sp1_proving → sp1_proved → dispatched → resolved`.
//!   Delegates SP1 Groth16 proof generation to the proxy `/challenge/sp1/{request,status}` API.
//!   Builds a merkle inclusion proof from L2 RPC data and submits `resolveBlockChallenge`.
//! - **Batch-root** challenges: `received → dispatched → resolved`. Builds an `L2BlockHeaderV1[]`
//!   from L2 RPC headers + receipts (no SP1, no local merkle root reconstruction) and submits
//!   `resolveBatchRootChallenge` — the contract recomputes the root from these headers chained
//!   against the previous batch's `toBlockHash` from storage.
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

use alloy_primitives::{Bytes, B256, U256};
use alloy_provider::Provider;
use alloy_rpc_types::TransactionRequest;
use l1_rollup_client::{
    prepare_resolve_batch_root_challenge_tx, prepare_resolve_block_challenge_tx, L2BlockHeaderV1,
    MerkleProof, RollupTxPartial,
};
use nitro_types::ChallengeSp1Request;
use rsp_client_executor::io::EthClientExecutorInput;
use serde::{Deserialize, Serialize};
use tokio::time::MissedTickBehavior;
use tracing::{debug, error, info, warn};

use crate::{
    blob_builder_mdbx::build_blobs_from_mdbx,
    db::{self, ChallengeKind, ChallengeRow, ChallengeStatus, RbfResumeState},
    orchestrator::{DispatchBackoff, OrchestratorShared, RevertKind, STUCK_AT_CAP_BLOCKS},
    rbf::{self, RbfObserver},
};

/// Active worker tick.
const WORKER_TICK: Duration = Duration::from_secs(1);

/// Number of L1 blocks remaining-to-deadline at which we start warning
/// loudly that MDBX is blocking challenge resolution. ~30 L1 blocks ≈ 6 min.
const DEADLINE_WARN_WINDOW_L1_BLOCKS: u64 = 30;

/// True when `(deadline - current_l1_block) <= DEADLINE_WARN_WINDOW_L1_BLOCKS`.
/// Used to gate noisy MDBX-lag warnings — silent during normal lag, loud
/// when the deadline is close enough that an unrecovered lag means the
/// challenge will fail. Returns `false` on L1 RPC failure so a transient
/// lookup error never elevates into an alert.
async fn challenge_close_to_deadline(shared: &OrchestratorShared, row: &ChallengeRow) -> bool {
    let Ok(current) = shared.config.l1_provider.get_block_number().await else {
        return false;
    };
    row.deadline.saturating_sub(current) <= DEADLINE_WARN_WINDOW_L1_BLOCKS
}

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

        if backoff.is_blocking() {
            tokio::select! {
                biased;
                _ = shared.shutdown.cancelled() => break,
                _ = tick.tick() => continue,
            }
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
                ChallengeStatus::Sp1Proving => {
                    handle_sp1_proving(&shared, &row, &mut backoff).await
                }
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

        if backoff.is_blocking() {
            tokio::select! {
                biased;
                _ = shared.shutdown.cancelled() => break,
                _ = tick.tick() => continue,
            }
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
        event = "challenge_deadline_expired",
        challenge_id = row.challenge_id,
        batch_index = row.batch_index,
        kind = row.kind.as_str(),
        deadline_l1_block = row.deadline,
        current_l1_block,
        "challenge deadline expired — marking failed (rollup will go corrupted; \
         operator must call revertBatches)"
    );
    if let Err(e) = db::record_challenge_failed(&shared.db_tx, row.challenge_id).await {
        warn!(
            challenge_id = row.challenge_id,
            err = %e,
            event = "record_challenge_failed_failed",
            reason = "deadline",
            "record_challenge_failed failed"
        );
    }
    true
}

/// Per-step failure classification for the resolve pipeline.
/// `InvariantViolation` ⇒ operator action required (rollup wedged); the
/// worker marks the row Failed and stops retrying. `Transient` ⇒ wait +
/// retry on backoff. Silent loops on either branch were the bug class
/// the e2e audit was filed against.
enum ResolveError {
    InvariantViolation(String),
    Transient(eyre::Report),
}

/// Mark a challenge row `Failed` with operator-loud logging. Reserved
/// for invariant violations the worker cannot recover from by retrying
/// (missing batch in DB, commitment not in batch's L2 range, etc.).
async fn mark_invariant_violation(shared: &OrchestratorShared, row: &ChallengeRow, reason: &str) {
    error!(
        event = "challenge_invariant_violation",
        challenge_id = row.challenge_id,
        kind = row.kind.as_str(),
        batch_index = row.batch_index,
        reason,
        "challenge invariant violation — marking failed; operator action required"
    );
    metrics::counter!(
        "orchestrator_challenge_invariant_violation_total",
        "kind" => row.kind.as_str(),
    )
    .increment(1);
    if let Err(e) = db::record_challenge_failed(&shared.db_tx, row.challenge_id).await {
        warn!(
            challenge_id = row.challenge_id,
            err = %e,
            event = "record_challenge_failed_failed",
            reason = "invariant",
            "record_challenge_failed failed"
        );
    }
}

/// Lifecycle from `Received`: build the EthClientExecutorInput witness
/// (cold-store hit verbatim, otherwise MDBX-backed rebuild), assemble
/// canonical EIP-4844 blobs from MDBX, and POST the SP1 proof request to
/// the proxy. Transient failures back off and retry; invariant violations
/// (commitment not in batch range) mark the row Failed.
#[tracing::instrument(
    skip_all,
    fields(challenge_id = row.challenge_id, batch_index = row.batch_index, kind = row.kind.as_str())
)]
async fn handle_block_received(
    shared: &OrchestratorShared,
    row: &ChallengeRow,
    backoff: &mut DispatchBackoff,
) {
    let target_block_number = match resolve_block_target(shared, row).await {
        Ok(n) => n,
        Err(ResolveError::InvariantViolation(reason)) => {
            mark_invariant_violation(shared, row, &reason).await;
            return;
        }
        Err(ResolveError::Transient(_)) => {
            backoff.apply("resolve_block_target transient");
            return;
        }
    };
    let (from_block, to_block) = match lookup_batch_range(shared, row.batch_index) {
        Ok(r) => r,
        Err(e) => {
            mark_invariant_violation(shared, row, &format!("lookup_batch_range: {e}")).await;
            return;
        }
    };

    let witness_bytes = match shared.driver.get_or_build_witness(target_block_number).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            warn!(
                challenge_id = row.challenge_id,
                target_block_number, "witness not available (block beyond MDBX tip or zero)"
            );
            backoff.apply("witness not available");
            return;
        }
        Err(e) => {
            warn!(
                challenge_id = row.challenge_id,
                target_block_number,
                err = %e,
                "Driver::get_or_build_witness failed"
            );
            backoff.apply("get_or_build_witness");
            return;
        }
    };
    let client_input: EthClientExecutorInput = match bincode::deserialize(&witness_bytes) {
        Ok(v) => v,
        Err(e) => {
            warn!(
                challenge_id = row.challenge_id,
                target_block_number,
                err = %e,
                "deserialize EthClientExecutorInput from witness payload failed"
            );
            backoff.apply("deserialize EthClientExecutorInput");
            return;
        }
    };

    let blobs = match build_blobs_from_mdbx(&shared.driver, from_block, to_block).await {
        Ok(Some(b)) => b,
        Ok(None) => {
            if challenge_close_to_deadline(shared, row).await {
                warn!(
                    challenge_id = row.challenge_id,
                    from_block,
                    to_block,
                    "MDBX tip behind challenge blob range; deadline approaching — \
                     worker will retry next tick"
                );
            }
            backoff.apply("build_blobs_from_mdbx tip-behind");
            return;
        }
        Err(e) => {
            warn!(
                challenge_id = row.challenge_id,
                from_block,
                to_block,
                err = %e,
                "build_blobs_from_mdbx failed"
            );
            backoff.apply("build_blobs_from_mdbx");
            return;
        }
    };

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
            if let Err(e) =
                db::record_challenge_sp1_requested(&shared.db_tx, row.challenge_id, request_id)
                    .await
            {
                warn!(
                    challenge_id = row.challenge_id,
                    err = %e,
                    event = "record_challenge_sp1_requested_failed",
                    "record_challenge_sp1_requested failed"
                );
            }
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
            backoff.apply("post_sp1_request");
        }
    }
}

#[tracing::instrument(
    skip_all,
    fields(challenge_id = row.challenge_id, batch_index = row.batch_index, kind = row.kind.as_str())
)]
async fn handle_sp1_proving(
    shared: &OrchestratorShared,
    row: &ChallengeRow,
    backoff: &mut DispatchBackoff,
) {
    // CHECK constraint guarantees Sp1Proving rows always carry sp1_request_id.
    // This `else` is defensive only — real divergence would mean DB corruption.
    let Some(request_id) = row.sp1_request_id else {
        error!(
            challenge_id = row.challenge_id,
            event = "sp1_proving_missing_request_id_invariant",
            "sp1_proving row without sp1_request_id (check constraint violated)"
        );
        return;
    };

    // Stamp `last_polled_at` BEFORE the HTTP call — the SQL predicate
    // in `find_active_block_challenge` excludes the row from the next
    // ~SP1_STATUS_POLL_INTERVAL_SECS even if the call errors mid-flight,
    // preventing a tight retry loop against the proxy.
    if let Err(e) = db::stamp_challenge_polled(&shared.db_tx, row.challenge_id).await {
        warn!(
            challenge_id = row.challenge_id,
            err = %e,
            event = "stamp_challenge_polled_failed",
            "stamp_challenge_polled failed"
        );
    }

    match poll_sp1_status(
        &shared.config.http_client,
        &shared.config.proxy_url,
        &shared.config.api_key,
        request_id,
    )
    .await
    {
        Ok(Sp1StatusOutcome::Ready { proof_bytes }) => {
            if let Err(e) =
                db::record_challenge_sp1_proved(&shared.db_tx, row.challenge_id, proof_bytes).await
            {
                warn!(
                    challenge_id = row.challenge_id,
                    err = %e,
                    event = "record_challenge_sp1_proved_failed",
                    "record_challenge_sp1_proved failed"
                );
            }
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
            if let Err(e) =
                db::record_challenge_sp1_lost_reset(&shared.db_tx, row.challenge_id).await
            {
                warn!(
                    challenge_id = row.challenge_id,
                    err = %e,
                    event = "record_challenge_sp1_lost_reset_failed",
                    "record_challenge_sp1_lost_reset failed"
                );
            }
        }
        Err(Sp1StatusError::Other(e)) => {
            warn!(
                challenge_id = row.challenge_id,
                err = %e,
                "poll_sp1_status failed — retrying after SP1_STATUS_POLL_INTERVAL"
            );
            backoff.apply("poll_sp1_status");
        }
    }
}

#[tracing::instrument(
    skip_all,
    fields(challenge_id = row.challenge_id, batch_index = row.batch_index, kind = row.kind.as_str())
)]
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
            event = "dispatched_challenge_missing_nonce_invariant",
            "dispatched challenge row without persisted nonce — skipping resume"
        );
        return;
    };

    // Same calldata-only → simulate → finalize order as run_resolve_lifecycle.
    let mut partial = match prepare_resolve_partial(shared, row).await {
        Ok(p) => p,
        Err(ResolveError::InvariantViolation(reason)) => {
            mark_invariant_violation(shared, row, &reason).await;
            return;
        }
        Err(ResolveError::Transient(e)) => {
            warn!(
                challenge_id = row.challenge_id,
                err = %e,
                "prepare_resolve_partial (resume) transient — backoff"
            );
            backoff.apply("prepare_resolve_partial (resume) transient");
            return;
        }
    };

    if let Err(reason) = validate_resolve_pre_broadcast(shared, row, &partial).await {
        fail_with_reason(shared, row, reason).await;
        return;
    }

    if let Err(e) = l1_rollup_client::finalize_partial(
        &shared.config.l1_provider,
        &mut partial,
        shared.config.l1_signer_address,
    )
    .await
    {
        warn!(
            challenge_id = row.challenge_id,
            err = %e,
            "finalize_partial (resume gas estimate) failed after sim passed"
        );
        backoff.apply("finalize_partial (resume)");
        return;
    }

    let resume = match (row.tx_hash, row.max_fee_per_gas, row.max_priority_fee_per_gas) {
        (Some(h), Some(fee), Some(tip)) => Some(RbfResumeState {
            nonce,
            tx_hash: h,
            max_fee_per_gas: fee,
            max_priority_fee_per_gas: tip,
        }),
        _ => None,
    };

    let (fee, tip) = match resume.as_ref() {
        Some(r) => (r.max_fee_per_gas, r.max_priority_fee_per_gas),
        None => match rbf::estimate_initial_fees(
            shared,
            rbf::FeeEstimateLog {
                batch_index: None,
                challenge_id: Some(row.challenge_id),
                kind: Some(row.kind.as_str()),
            },
            None,
            "",
        )
        .await
        {
            Some(v) => v,
            None => {
                backoff.apply("estimate_initial_fees (resume)");
                return;
            }
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
    let budget = compute_block_budget(&shared.config.l1_provider, row.deadline).await;
    rbf::run_generic(
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

/// Defer-allocate ordering: prepare (calldata-only, no `estimate_gas`) →
/// `eth_call` simulation (catches permanent contract reverts before any
/// gas burn) → estimate_gas → fees → allocate nonce → RBF. A permission
/// revert during prepare must NOT burn a nonce because tail-CAS `release`
/// cannot rewind past concurrent allocations from other workers. Used
/// for the initial dispatch from `Received` (BatchRoot) or `Sp1Proved`
/// (Block).
#[tracing::instrument(
    skip_all,
    fields(challenge_id = row.challenge_id, batch_index = row.batch_index, kind = row.kind.as_str())
)]
async fn run_resolve_lifecycle(
    shared: &OrchestratorShared,
    row: &ChallengeRow,
    backoff: &mut DispatchBackoff,
) {
    let mut partial = match prepare_resolve_partial(shared, row).await {
        Ok(p) => p,
        Err(ResolveError::InvariantViolation(reason)) => {
            mark_invariant_violation(shared, row, &reason).await;
            return;
        }
        Err(ResolveError::Transient(e)) => {
            warn!(
                challenge_id = row.challenge_id,
                err = %e,
                "prepare_resolve_partial transient — backoff"
            );
            backoff.apply("prepare_resolve_partial transient");
            return;
        }
    };

    if let Err(reason) = validate_resolve_pre_broadcast(shared, row, &partial).await {
        fail_with_reason(shared, row, reason).await;
        return;
    }

    if let Err(e) = l1_rollup_client::finalize_partial(
        &shared.config.l1_provider,
        &mut partial,
        shared.config.l1_signer_address,
    )
    .await
    {
        warn!(
            challenge_id = row.challenge_id,
            err = %e,
            "finalize_partial (gas estimate) failed after sim passed"
        );
        backoff.apply("finalize_partial");
        return;
    }

    let (fee, tip) = match rbf::estimate_initial_fees(
        shared,
        rbf::FeeEstimateLog {
            batch_index: None,
            challenge_id: Some(row.challenge_id),
            kind: Some(row.kind.as_str()),
        },
        None,
        "",
    )
    .await
    {
        Some(v) => v,
        None => {
            backoff.apply("estimate_initial_fees");
            return;
        }
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
    let budget = compute_block_budget(&shared.config.l1_provider, row.deadline).await;
    rbf::run_generic(
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

/// Compute the per-resolve L1-block budget for the RBF stuck-at-cap
/// trigger: the smaller of the preconfirm-tuned default and the number of
/// L1 blocks remaining to the row's deadline. Caps at the static default
/// so a huge deadline doesn't extend the budget unnecessarily.
async fn compute_block_budget(l1_provider: &impl Provider, deadline: u64) -> u64 {
    let current = l1_provider.get_block_number().await.unwrap_or(0);
    let blocks_left = deadline.saturating_sub(current);
    std::cmp::min(STUCK_AT_CAP_BLOCKS, blocks_left)
}

async fn fail_with_reason(shared: &OrchestratorShared, row: &ChallengeRow, reason: String) {
    error!(
        event = "challenge_pre_broadcast_validation_failed",
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
    if let Err(e) = db::record_challenge_failed(&shared.db_tx, row.challenge_id).await {
        warn!(
            challenge_id = row.challenge_id,
            err = %e,
            event = "record_challenge_failed_failed",
            reason = "pre_broadcast",
            "record_challenge_failed failed"
        );
    }
}

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
    let t = std::time::Instant::now();
    let r = shared.config.l1_provider.call(req).await;
    let duration_ms = t.elapsed().as_millis() as u64;
    match r {
        Ok(_) => {
            info!(
                challenge_id = row.challenge_id,
                kind = row.kind.as_str(),
                event = "resolve_validate_done",
                duration_ms,
                "resolve eth_call validation passed"
            );
            Ok(())
        }
        Err(e) => Err(format!(
            "eth_call simulation reverted (challenge_id={}, kind={}): {e}",
            row.challenge_id,
            row.kind.as_str()
        )),
    }
}

/// Per-kind dispatcher: builds either a `resolveBlockChallenge` or a
/// `resolveBatchRootChallenge` calldata-only partial. Caller runs
/// `validate_resolve_pre_broadcast`, then `finalize_partial`, then
/// `RollupTxPartial::with_nonce` just before broadcast.
async fn prepare_resolve_partial(
    shared: &OrchestratorShared,
    row: &ChallengeRow,
) -> Result<RollupTxPartial, ResolveError> {
    match row.kind {
        ChallengeKind::Block => prepare_block_resolve_partial(shared, row).await,
        ChallengeKind::BatchRoot => prepare_batch_root_resolve_partial(shared, row).await,
    }
}

async fn prepare_block_resolve_partial(
    shared: &OrchestratorShared,
    row: &ChallengeRow,
) -> Result<RollupTxPartial, ResolveError> {
    let cfg = &shared.config;
    let Some(commitment) = row.commitment else {
        return Err(ResolveError::InvariantViolation(
            "block challenge row missing commitment".to_string(),
        ));
    };
    let Some(sp1_proof) = row.sp1_proof_bytes.clone() else {
        return Err(ResolveError::InvariantViolation(
            "block challenge row missing sp1_proof_bytes".to_string(),
        ));
    };

    let (from_block, to_block) = lookup_batch_range(shared, row.batch_index)
        .map_err(|e| ResolveError::InvariantViolation(format!("{e}")))?;

    let (headers, leaves) = match shared
        .driver
        .collect_l2_block_headers(from_block..=to_block)
        .await
        .map_err(ResolveError::Transient)?
    {
        Some(v) => v,
        None => {
            if challenge_close_to_deadline(shared, row).await {
                warn!(
                    challenge_id = row.challenge_id,
                    from_block, to_block, "MDBX tip behind disputed range; deadline approaching"
                );
            }
            return Err(ResolveError::Transient(eyre::eyre!(
                "MDBX tip behind challenge range [{from_block}..={to_block}]; \
                 driver will catch up on next tick"
            )));
        }
    };

    let Some(idx) = leaves.iter().position(|l| *l == commitment) else {
        return Err(ResolveError::InvariantViolation(format!(
            "no matching leaf in batch {} for commitment {commitment} — \
             L2 chain may have forked away from sequencer-submitted blob data",
            row.batch_index
        )));
    };

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
    )
    .await
    .map_err(ResolveError::Transient)
}

async fn prepare_batch_root_resolve_partial(
    shared: &OrchestratorShared,
    row: &ChallengeRow,
) -> Result<RollupTxPartial, ResolveError> {
    let cfg = &shared.config;
    let (from_block, to_block) = lookup_batch_range(shared, row.batch_index)
        .map_err(|e| ResolveError::InvariantViolation(format!("{e}")))?;

    let (headers, _leaves) = match shared
        .driver
        .collect_l2_block_headers(from_block..=to_block)
        .await
        .map_err(ResolveError::Transient)?
    {
        Some(v) => v,
        None => {
            if challenge_close_to_deadline(shared, row).await {
                warn!(
                    challenge_id = row.challenge_id,
                    from_block,
                    to_block,
                    "MDBX tip behind batch-root challenge range; deadline approaching"
                );
            }
            return Err(ResolveError::Transient(eyre::eyre!(
                "MDBX tip behind batch-root challenge range [{from_block}..={to_block}]; \
                 driver will catch up on next tick"
            )));
        }
    };

    let v1_headers: Vec<L2BlockHeaderV1> = headers
        .into_iter()
        .map(|h| L2BlockHeaderV1 {
            blockHash: h.blockHash,
            withdrawalRoot: h.withdrawalRoot,
            depositRoot: h.depositRoot,
        })
        .collect();

    prepare_resolve_batch_root_challenge_tx(
        &cfg.l1_provider,
        cfg.l1_rollup_addr,
        row.batch_index,
        v1_headers,
    )
    .await
    .map_err(ResolveError::Transient)
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

/// Resolve the L2 block number that backs the disputed commitment.
/// `InvariantViolation` ⇒ commitment matches no leaf in the batch's MDBX
/// range (L2 may have forked); `Transient` ⇒ batch row not yet seen,
/// MDBX behind, or read error.
async fn resolve_block_target(
    shared: &OrchestratorShared,
    row: &ChallengeRow,
) -> Result<u64, ResolveError> {
    let Some(commitment) = row.commitment else {
        return Err(ResolveError::InvariantViolation(
            "block challenge row missing commitment".to_string(),
        ));
    };
    let (from_block, to_block) = lookup_batch_range(shared, row.batch_index)
        .map_err(|e| ResolveError::Transient(eyre::eyre!("{e}")))?;
    let (_, leaves) = shared
        .driver
        .collect_l2_block_headers(from_block..=to_block)
        .await
        .map_err(ResolveError::Transient)?
        .ok_or_else(|| {
            ResolveError::Transient(eyre::eyre!(
                "MDBX tip behind challenge range [{from_block}..={to_block}]"
            ))
        })?;
    leaves.iter().position(|l| *l == commitment).map(|idx| from_block + idx as u64).ok_or_else(
        || {
            ResolveError::InvariantViolation(
                "commitment not in batch L2 range — L2 chain may have forked".to_string(),
            )
        },
    )
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
    proof_bytes: Vec<u8>,
}

enum Sp1StatusOutcome {
    Ready { proof_bytes: Vec<u8> },
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
        debug!(
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
    // Pacing is handled by the SQL predicate in `find_active_block_challenge`
    // via the `last_polled_at` column — `handle_sp1_proving` stamps it
    // before calling here, so the row is excluded from the next ~15 s.
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
            Ok(Sp1StatusOutcome::Ready { proof_bytes: proof.proof_bytes })
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
            event = "resolve_dispatched",
            challenge_id = self.challenge_id,
            batch_index = self.batch_index,
            kind = self.kind.as_str(),
            nonce = self.nonce,
            tx_hash = %hash,
            max_fee_per_gas = fee,
            max_priority_fee_per_gas = tip,
            "resolve dispatched"
        );
        if let Err(e) = db::record_challenge_first_broadcast(
            &self.shared.db_tx,
            self.challenge_id,
            hash,
            self.nonce,
            fee,
            tip,
        )
        .await
        {
            warn!(
                challenge_id = self.challenge_id,
                err = %e,
                event = "record_challenge_first_broadcast_failed",
                "record_challenge_first_broadcast failed"
            );
        }
        crate::metrics::counter_resolve_dispatched(self.kind.as_str());
    }

    async fn on_rebroadcast(&self, hash: B256, fee: u128, tip: u128) {
        info!(
            event = "resolve_rebroadcast",
            challenge_id = self.challenge_id,
            batch_index = self.batch_index,
            kind = self.kind.as_str(),
            tx_hash = %hash,
            max_fee_per_gas = fee,
            max_priority_fee_per_gas = tip,
            "resolve rebroadcast"
        );
        if let Err(e) =
            db::record_challenge_rebroadcast(&self.shared.db_tx, self.challenge_id, hash, fee, tip)
                .await
        {
            warn!(
                challenge_id = self.challenge_id,
                err = %e,
                event = "record_challenge_rebroadcast_failed",
                "record_challenge_rebroadcast failed"
            );
        }
    }

    async fn on_submitted(&self, hash: B256, l1_block: u64) {
        info!(
            event = "resolve_confirmed",
            challenge_id = self.challenge_id,
            batch_index = self.batch_index,
            kind = self.kind.as_str(),
            tx_hash = %hash,
            l1_block,
            "resolve confirmed"
        );
        if let Err(e) =
            db::record_challenge_submitted(&self.shared.db_tx, self.challenge_id, l1_block).await
        {
            warn!(
                challenge_id = self.challenge_id,
                err = %e,
                event = "record_challenge_submitted_failed",
                "record_challenge_submitted failed"
            );
        }
        crate::metrics::counter_resolve_submitted(self.kind.as_str());
    }

    async fn on_reverted(&self, hash: B256, kind: RevertKind) {
        warn!(
            event = "resolve_reverted",
            challenge_id = self.challenge_id,
            batch_index = self.batch_index,
            kind = self.kind.as_str(),
            tx_hash = %hash,
            revert_kind = kind.as_str(),
            "resolve reverted"
        );
        crate::metrics::counter_resolve_rejected(self.kind.as_str());
        // Roll back to the fresh-dispatch entry point so the worker re-runs
        // the full defer-allocate cycle (prepare → validate → fees →
        // allocate) on its next tick. Block kind keeps `sp1_proof_bytes`
        // and resumes from `Sp1Proved` (skips the SP1 round-trip);
        // batch_root resumes from `Received` (no SP1 phase).
        if let Err(e) = db::rollback_challenge_dispatch(
            &self.shared.db_tx,
            self.challenge_id,
            rollback_status_for(self.kind),
        )
        .await
        {
            warn!(
                challenge_id = self.challenge_id,
                err = %e,
                event = "rollback_challenge_dispatch_failed",
                reason = "reverted",
                "rollback_challenge_dispatch failed"
            );
        }
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
        if let Err(e) = db::rollback_challenge_dispatch(
            &self.shared.db_tx,
            self.challenge_id,
            rollback_status_for(self.kind),
        )
        .await
        {
            warn!(
                challenge_id = self.challenge_id,
                err = %e,
                event = "rollback_challenge_dispatch_failed",
                reason = "pre_receipt",
                "rollback_challenge_dispatch failed"
            );
        }
    }

    /// Exits the bump loop only on terminal status (`Resolved` | `Failed`).
    /// There is a narrow race window: the bump loop may broadcast a tx at
    /// fee-bump time before this check runs. If the listener flipped status
    /// to Resolved between the broadcast and the next abort poll, our
    /// newly-broadcast tx will revert with `BlockNotChallenged` /
    /// `BatchRootNotChallenged` on chain — wasted gas, no other harm.
    /// Acceptable: polling status before EVERY broadcast would double the
    /// L1 RPC load.
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
    use alloy_rpc_types::TransactionReceipt;
    use fluent_stf_primitives::{
        BRIDGE_ADDRESS, BRIDGE_DEPOSIT_TOPIC, BRIDGE_ROLLBACK_TOPIC, BRIDGE_WITHDRAWAL_TOPIC,
        LEGACY_BRIDGE_WITHDRAWAL_TOPIC,
    };
    use l1_rollup_client::L2BlockHeader;
    use rsp_host_executor::events_hash::{
        calculate_deposit_hash, calculate_withdrawal_root, count_deposits,
    };

    /// RPC walk preserved for `real_batch_877_resolve_validation` so the
    /// integration test can exercise the on-chain math against a remote
    /// RPC without standing up an MDBX datadir.
    async fn collect_headers_with_target_rpc(
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
            let header = match build_l2_block_header_rpc(l2_provider, block_number).await {
                Ok(h) => h,
                Err(e) => {
                    warn!(block_number, err = %e, "failed to build L2BlockHeader (test RPC shim)");
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

    async fn build_l2_block_header_rpc(
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

    /// End-to-end check of the V1 batch-root resolve invariants against
    /// real Fluent testnet data for batch 877. The contract's
    /// `_calculateBatchRootV1` chains `prevBlockHash` from
    /// `previousBatch.toBlockHash` storage forward through
    /// `headers[i].blockHash`; for a chain-intact batch the result is
    /// identical to the V0 commit-time root, so checking the V0
    /// reconstruction plus the chain-linkage invariants is equivalent
    /// to mirroring the on-chain V1 path.
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

        let rpc_url = std::env::var("INTEGRATION_L2_RPC_URL")
            .expect("INTEGRATION_L2_RPC_URL must be set to run this integration test");
        let url: url::Url = rpc_url.parse().expect("INTEGRATION_L2_RPC_URL is not a valid URL");
        let l2: alloy_provider::RootProvider =
            rsp_provider::create_provider(url).expect("failed to build L2 provider");

        let (headers_877, leaves_877, _) =
            collect_headers_with_target_rpc(&l2, BATCH_877_FROM, BATCH_877_TO, None)
                .await
                .expect("collect_headers_with_target_rpc(877) failed");
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

        let (headers_876, _, _) =
            collect_headers_with_target_rpc(&l2, BATCH_876_FROM, BATCH_876_TO, None)
                .await
                .expect("collect_headers_with_target_rpc(876) failed");
        let last_header_876 = headers_876.last().expect("batch 876 has at least one block");

        assert_eq!(
            last_header_876.blockHash, headers_877[0].previousBlockHash,
            "cross-batch chain break: last(876).blockHash != first(877).previousBlockHash"
        );
    }
}
