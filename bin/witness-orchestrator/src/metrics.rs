//! Prometheus metrics surface for the witness-orchestrator.
//!
//! Layout mirrors the Go sequencer reference
//! (`rollup-bridge-services/internal/services/sequencer/metrics.go`):
//! one recorder installed at startup, a dedicated HTTP `/metrics` endpoint,
//! and a small set of named constants + helpers that the orchestrator hot
//! paths call directly.

use std::{sync::Arc, time::Duration};

use alloy_primitives::U256;
use alloy_rpc_types::TransactionReceipt;
use axum::{extract::State, response::IntoResponse, routing::get, Router};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use tokio_util::sync::CancellationToken;
use tracing::info;

pub(crate) const LAST_BLOCK_WITNESS_BUILT: &str = "orchestrator_last_block_witness_built";
pub(crate) const LAST_BLOCK_EXECUTED: &str = "orchestrator_last_block_executed";
pub(crate) const LAST_BLOCK_SIGNED: &str = "orchestrator_last_block_signed";
pub(crate) const LAST_BATCH_SIGNED: &str = "orchestrator_last_batch_signed";
pub(crate) const LAST_BATCH_SIGNED_FROM_BLOCK: &str = "orchestrator_last_batch_signed_from_block";
pub(crate) const LAST_BATCH_SIGNED_TO_BLOCK: &str = "orchestrator_last_batch_signed_to_block";
pub(crate) const LAST_BATCH_PRECONFIRMED: &str = "orchestrator_last_batch_preconfirmed";
pub(crate) const LAST_BATCH_PRECONFIRMED_FROM_BLOCK: &str =
    "orchestrator_last_batch_preconfirmed_from_block";
pub(crate) const LAST_BATCH_PRECONFIRMED_TO_BLOCK: &str =
    "orchestrator_last_batch_preconfirmed_to_block";

pub(crate) const SIGN_BLOCK_EXECUTION_DURATION: &str =
    "orchestrator_sign_block_execution_duration_seconds";
pub(crate) const SIGN_BATCH_ROOT_DURATION: &str = "orchestrator_sign_batch_root_duration_seconds";

pub(crate) const SIGN_FAILURES_TOTAL: &str = "orchestrator_sign_failures_total";
pub(crate) const L1_DISPATCH_REJECTED_TOTAL: &str = "orchestrator_l1_dispatch_rejected_total";
pub(crate) const L1_BROADCAST_FAILURES_TOTAL: &str = "orchestrator_l1_broadcast_failures_total";
pub(crate) const DB_WRITER_DROPPED_TOTAL: &str = "orchestrator_db_writer_dropped_total";

pub(crate) const L1_RESOLVE_DISPATCHED_TOTAL: &str = "orchestrator_l1_resolve_dispatched_total";
pub(crate) const L1_RESOLVE_SUBMITTED_TOTAL: &str = "orchestrator_l1_resolve_submitted_total";
pub(crate) const L1_RESOLVE_REJECTED_TOTAL: &str = "orchestrator_l1_resolve_rejected_total";
pub(crate) const L1_RESOLVE_PRE_RECEIPT_FAILURE_TOTAL: &str =
    "orchestrator_l1_resolve_pre_receipt_failure_total";

pub(crate) const CHALLENGE_DEADLINE_EXPIRED_TOTAL: &str =
    "orchestrator_challenge_deadline_expired_total";
pub(crate) const CHALLENGE_INVARIANT_VIOLATION_TOTAL: &str =
    "orchestrator_challenge_invariant_violation_total";
pub(crate) const CHALLENGE_SP1_REQUEST_LOST_TOTAL: &str =
    "orchestrator_challenge_sp1_request_lost_total";
pub(crate) const CHALLENGE_PRE_BROADCAST_FAILED_TOTAL: &str =
    "orchestrator_challenge_pre_broadcast_failed_total";
pub(crate) const CHALLENGE_REVERTED_POST_MINE_TOTAL: &str =
    "orchestrator_challenge_reverted_post_mine_total";
pub(crate) const CHALLENGE_REORG_DETECTED_TOTAL: &str =
    "orchestrator_challenge_reorg_detected_total";
pub(crate) const BATCH_REORG_DETECTED_TOTAL: &str = "orchestrator_batch_reorg_detected_total";

// Histogram (not counter) so the cumulative spend is readable via `_sum`;
// a `u64` counter cannot represent sub-ETH amounts (`0.002 as u64 == 0`).
pub(crate) const L1_DISPATCH_COST_ETH: &str = "orchestrator_l1_dispatch_cost_eth";

pub(crate) const NONCE_ALLOCATOR_NEXT: &str = "orchestrator_nonce_allocator_next";
pub(crate) const NONCE_PENDING_L1: &str = "orchestrator_nonce_pending_l1";
// Regression sentinel for the defer-allocate invariant — should remain 0.
pub(crate) const NONCE_LEAKS_TOTAL: &str = "orchestrator_nonce_leaks_total";

/// Go reference: `ExponentialBuckets(0.5, 2, 12)` plus two operator-defensive
/// buckets at the top so SP1 cold-start outliers up to ~2 h stay measurable
/// instead of pegging the percentile output at the bucket cap.
const SIGN_DURATION_BUCKETS: &[f64] = &[
    0.5, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 512.0, 1024.0, 2048.0, 4096.0, 8192.0,
];

/// Go reference: `ExponentialBuckets(1e-5, 2, 16)` — 10 μETH .. ~0.6 ETH.
const COST_ETH_BUCKETS: &[f64] = &[
    1e-5, 2e-5, 4e-5, 8e-5, 1.6e-4, 3.2e-4, 6.4e-4, 1.28e-3, 2.56e-3, 5.12e-3, 1.024e-2, 2.048e-2,
    4.096e-2, 8.192e-2, 1.6384e-1, 3.2768e-1, 6.5536e-1,
];

/// Install the Prometheus recorder globally. Must be called before any
/// `metrics::*!` macro fires for its output to land — un-recorded writes are
/// silent no-ops.
pub(crate) fn install() -> eyre::Result<PrometheusHandle> {
    let handle = PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Full(SIGN_BLOCK_EXECUTION_DURATION.to_string()),
            SIGN_DURATION_BUCKETS,
        )
        .map_err(|e| eyre::eyre!("metrics buckets (sign_block_execution): {e}"))?
        .set_buckets_for_metric(
            Matcher::Full(SIGN_BATCH_ROOT_DURATION.to_string()),
            SIGN_DURATION_BUCKETS,
        )
        .map_err(|e| eyre::eyre!("metrics buckets (sign_batch_root): {e}"))?
        .set_buckets_for_metric(Matcher::Full(L1_DISPATCH_COST_ETH.to_string()), COST_ETH_BUCKETS)
        .map_err(|e| eyre::eyre!("metrics buckets (l1_dispatch_cost): {e}"))?
        .upkeep_timeout(Duration::from_secs(5))
        .install_recorder()
        .map_err(|e| eyre::eyre!("install Prometheus recorder: {e}"))?;

    metrics::describe_gauge!(
        LAST_BLOCK_WITNESS_BUILT,
        "Latest L2 block number for which a witness is available (built fresh or reused from cold store)"
    );
    metrics::describe_gauge!(
        LAST_BLOCK_EXECUTED,
        "Latest L2 block number executed by the proxy/enclave"
    );
    metrics::describe_gauge!(
        LAST_BLOCK_SIGNED,
        "Latest L2 block number included in a signed batch (equals last_batch_signed_to_block). \
         Difference from last_block_executed surfaces blocks-executed-but-not-yet-in-signed-batch."
    );
    metrics::describe_gauge!(
        LAST_BATCH_SIGNED,
        "Index of the most recently signed L1 batch (/sign-batch-root)"
    );
    metrics::describe_gauge!(
        LAST_BATCH_SIGNED_FROM_BLOCK,
        "from_block of the most recently signed batch"
    );
    metrics::describe_gauge!(
        LAST_BATCH_SIGNED_TO_BLOCK,
        "to_block of the most recently signed batch"
    );
    metrics::describe_gauge!(
        LAST_BATCH_PRECONFIRMED,
        "Index of the most recently L1-included preconfirmBatch observed via BatchPreconfirmed event"
    );
    metrics::describe_gauge!(
        LAST_BATCH_PRECONFIRMED_FROM_BLOCK,
        "from_block of the most recently L1-included batch"
    );
    metrics::describe_gauge!(
        LAST_BATCH_PRECONFIRMED_TO_BLOCK,
        "to_block of the most recently L1-included batch"
    );

    metrics::describe_histogram!(
        SIGN_BLOCK_EXECUTION_DURATION,
        "Per-attempt duration of /sign-block-execution HTTP call (seconds)"
    );
    metrics::describe_histogram!(
        SIGN_BATCH_ROOT_DURATION,
        "Per-attempt duration of /sign-batch-root HTTP call (seconds)"
    );

    metrics::describe_counter!(
        SIGN_FAILURES_TOTAL,
        "Sign-endpoint failures. Labels: stage=block|batch, kind=enclave_busy|other"
    );
    metrics::describe_counter!(
        L1_DISPATCH_REJECTED_TOTAL,
        "preconfirmBatch txs that were mined with status=0 (on-chain revert)"
    );
    metrics::describe_counter!(
        L1_BROADCAST_FAILURES_TOTAL,
        "preconfirmBatch broadcast attempts rejected by the L1 RPC before mempool \
         admission. Labels: kind=nonce_too_low|stuck_at_cap|other"
    );
    metrics::describe_counter!(
        DB_WRITER_DROPPED_TOTAL,
        "Accumulator mutations dropped because the DB writer channel was closed \
         (typically during shutdown). In-memory state may be ahead of DB; restart \
         resyncs via normalize_startup_checkpoint."
    );
    metrics::describe_counter!(
        L1_RESOLVE_DISPATCHED_TOTAL,
        "Resolve-tx broadcasts (first attempt per challenge). Labels: kind=block|batch_root"
    );
    metrics::describe_counter!(
        L1_RESOLVE_SUBMITTED_TOTAL,
        "Resolve-tx receipts observed with status=1. Labels: kind=block|batch_root"
    );
    metrics::describe_counter!(
        L1_RESOLVE_REJECTED_TOTAL,
        "Resolve-tx receipts observed with status=0 (on-chain revert). Labels: \
         kind=block|batch_root"
    );
    metrics::describe_counter!(
        L1_RESOLVE_PRE_RECEIPT_FAILURE_TOTAL,
        "Resolve-tx hard-failures before any receipt (initial broadcast error, \
         stuck-at-cap, nonce advanced). Labels: kind=block|batch_root"
    );
    metrics::describe_counter!(
        CHALLENGE_DEADLINE_EXPIRED_TOTAL,
        "Challenges that crossed the on-chain resolution deadline before a \
         successful resolveBlockChallenge / resolveBatchRootChallenge tx \
         mined. Sentinel — operator must call Rollup.revertBatches. \
         Labels: kind=block|batch_root"
    );
    metrics::describe_counter!(
        CHALLENGE_INVARIANT_VIOLATION_TOTAL,
        "Challenge rows transitioned to Failed because an invariant the \
         resolver assumes is violated (missing batch in DB, commitment \
         outside batch range, etc.). Sentinel — rollup wedged. \
         Labels: kind=block|batch_root"
    );
    metrics::describe_counter!(
        CHALLENGE_SP1_REQUEST_LOST_TOTAL,
        "Proxy returned 404 for an SP1 request id we issued — the request \
         state was lost (proxy restart with stale DB or DB wipe). The \
         orchestrator clears the request_id and re-issues. \
         Labels: kind=block|batch_root"
    );
    metrics::describe_counter!(
        CHALLENGE_PRE_BROADCAST_FAILED_TOTAL,
        "Resolve-tx failed pre-broadcast validation (eth_call simulation \
         reverted with the signed calldata). Row marked Failed. Labels: \
         kind=block|batch_root"
    );
    metrics::describe_counter!(
        CHALLENGE_REVERTED_POST_MINE_TOTAL,
        "Resolve-tx receipt observed status=0 by the finalization ticker \
         (RBF receipt-watcher missed the failure earlier). RBF state \
         cleared for retry."
    );
    metrics::describe_counter!(
        CHALLENGE_REORG_DETECTED_TOTAL,
        "Challenge resolve-tx receipt vanished between observations — \
         suspected L1 reorg. l1_block cleared so the active worker \
         re-broadcasts."
    );
    metrics::describe_counter!(
        BATCH_REORG_DETECTED_TOTAL,
        "preconfirmBatch tx receipt vanished after BatchPreconfirmed event \
         — suspected L1 reorg. Status rolled back to Dispatched; \
         dispatcher resumes RBF against the persisted nonce."
    );

    metrics::describe_histogram!(
        L1_DISPATCH_COST_ETH,
        "Per-tx ETH cost of L1 preconfirmBatch (gas_used × effective_gas_price / 1e18). \
         Cumulative via `_sum`."
    );

    metrics::describe_gauge!(
        NONCE_ALLOCATOR_NEXT,
        "NonceAllocator's next-to-issue nonce (peek of the atomic counter). \
         Compare with NONCE_PENDING_L1 to spot drift."
    );
    metrics::describe_gauge!(
        NONCE_PENDING_L1,
        "L1 pending nonce for the orchestrator's submitter wallet \
         (eth_getTransactionCount(signer, pending)). Refreshed on bootstrap, \
         after nonce-too-low resync, and once per FINALIZATION_TICK (~30s). \
         Compare with NONCE_ALLOCATOR_NEXT to spot drift."
    );
    metrics::describe_counter!(
        NONCE_LEAKS_TOTAL,
        "Times NonceAllocator::release_with_outcome could not rewind the counter \
         due to a concurrent allocate(). Should remain 0 after the defer-allocate \
         refactor — non-zero increments indicate a regression of that invariant."
    );

    Ok(handle)
}

pub(crate) async fn run_server(
    listen_addr: String,
    handle: Arc<PrometheusHandle>,
    shutdown: CancellationToken,
) -> eyre::Result<()> {
    let app = Router::new().route("/metrics", get(render_metrics)).with_state(handle);

    let listener = tokio::net::TcpListener::bind(&listen_addr)
        .await
        .map_err(|e| eyre::eyre!("metrics server bind {listen_addr}: {e}"))?;

    info!(listen_addr, "Metrics HTTP server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(async move { shutdown.cancelled().await })
        .await
        .map_err(|e| eyre::eyre!("metrics server error: {e}"))
}

async fn render_metrics(State(handle): State<Arc<PrometheusHandle>>) -> impl IntoResponse {
    handle.render()
}

pub(crate) fn counter_resolve_dispatched(kind: &'static str) {
    metrics::counter!(L1_RESOLVE_DISPATCHED_TOTAL, "kind" => kind).increment(1);
}

pub(crate) fn counter_resolve_submitted(kind: &'static str) {
    metrics::counter!(L1_RESOLVE_SUBMITTED_TOTAL, "kind" => kind).increment(1);
}

pub(crate) fn counter_resolve_rejected(kind: &'static str) {
    metrics::counter!(L1_RESOLVE_REJECTED_TOTAL, "kind" => kind).increment(1);
}

pub(crate) fn counter_resolve_pre_receipt_failure(kind: &'static str) {
    metrics::counter!(L1_RESOLVE_PRE_RECEIPT_FAILURE_TOTAL, "kind" => kind).increment(1);
}

pub(crate) fn count_challenge_deadline_expired(kind: &'static str) {
    metrics::counter!(CHALLENGE_DEADLINE_EXPIRED_TOTAL, "kind" => kind).increment(1);
}

pub(crate) fn count_challenge_invariant_violation(kind: &'static str) {
    metrics::counter!(CHALLENGE_INVARIANT_VIOLATION_TOTAL, "kind" => kind).increment(1);
}

pub(crate) fn count_challenge_sp1_request_lost(kind: &'static str) {
    metrics::counter!(CHALLENGE_SP1_REQUEST_LOST_TOTAL, "kind" => kind).increment(1);
}

pub(crate) fn count_challenge_pre_broadcast_failed(kind: &'static str) {
    metrics::counter!(CHALLENGE_PRE_BROADCAST_FAILED_TOTAL, "kind" => kind).increment(1);
}

pub(crate) fn count_challenge_reverted_post_mine() {
    metrics::counter!(CHALLENGE_REVERTED_POST_MINE_TOTAL).increment(1);
}

pub(crate) fn count_challenge_reorg_detected() {
    metrics::counter!(CHALLENGE_REORG_DETECTED_TOTAL).increment(1);
}

pub(crate) fn count_batch_reorg_detected() {
    metrics::counter!(BATCH_REORG_DETECTED_TOTAL).increment(1);
}

/// Classify a sign-endpoint error by substring. Any error whose display output
/// contains the literal `"enclave busy"` is classified as `enclave_busy`;
/// everything else is `other`.
///
/// The enclave emits `"enclave busy"` when its request queue is saturated
/// (`bin/client/src/nitro/mod.rs`). It propagates verbatim through proxy
/// wrapping and the orchestrator's HTTP error formatter, so substring matching
/// is the only mechanism available until enclave code can be updated.
pub(crate) fn sign_failure_kind<E: std::fmt::Display>(err: &E) -> &'static str {
    if err.to_string().contains("enclave busy") {
        "enclave_busy"
    } else {
        "other"
    }
}

/// Record the ETH cost of a mined L1 dispatch receipt. Mirrors the Go
/// `observeGasCost(receipt)` helper in sequencer/metrics.go.
///
/// Precision: wei → ETH via `wei_as_f64 / 1e18`. Per-tx costs and multi-year
/// cumulative sums both fit in f64 with µETH-level granularity. Storing raw
/// wei would overflow f64's 53-bit integer precision within hours.
pub(crate) fn observe_dispatch_cost(receipt: &TransactionReceipt) {
    let wei = U256::from(receipt.gas_used).saturating_mul(U256::from(receipt.effective_gas_price));
    let eth = wei_to_eth_f64(wei);
    metrics::histogram!(L1_DISPATCH_COST_ETH).record(eth);
}

/// Set all three `last_batch_preconfirmed*` gauges in one call.
pub(crate) fn set_last_batch_preconfirmed(batch_index: u64, from_block: u64, to_block: u64) {
    metrics::gauge!(LAST_BATCH_PRECONFIRMED).set(batch_index as f64);
    metrics::gauge!(LAST_BATCH_PRECONFIRMED_FROM_BLOCK).set(from_block as f64);
    metrics::gauge!(LAST_BATCH_PRECONFIRMED_TO_BLOCK).set(to_block as f64);
}

/// Set all four `last_batch_signed*` / `last_block_signed` gauges in one call.
pub(crate) fn set_last_batch_signed(batch_index: u64, from_block: u64, to_block: u64) {
    metrics::gauge!(LAST_BATCH_SIGNED).set(batch_index as f64);
    metrics::gauge!(LAST_BATCH_SIGNED_FROM_BLOCK).set(from_block as f64);
    metrics::gauge!(LAST_BATCH_SIGNED_TO_BLOCK).set(to_block as f64);
    metrics::gauge!(LAST_BLOCK_SIGNED).set(to_block as f64);
}

/// Seed progress gauges from rehydrated state. Prometheus skips rendering a
/// metric that has never been emitted, so low-cadence gauges
/// (`last_batch_preconfirmed*`, `last_batch_signed*`) would stay absent
/// until the next real event — potentially hours on a stalled pipeline.
pub(crate) fn seed_gauges_on_startup(
    checkpoint: u64,
    preconfirmed: Option<(u64, u64, u64)>,
    signed: Option<(u64, u64, u64)>,
) {
    if checkpoint > 0 {
        metrics::gauge!(LAST_BLOCK_EXECUTED).set(checkpoint as f64);
        metrics::gauge!(LAST_BLOCK_WITNESS_BUILT).set(checkpoint as f64);
    }
    if let Some((idx, from, to)) = signed {
        set_last_batch_signed(idx, from, to);
    }
    if let Some((idx, from, to)) = preconfirmed {
        set_last_batch_preconfirmed(idx, from, to);
    }
}

pub(crate) fn set_nonce_allocator_next(value: u64) {
    metrics::gauge!(NONCE_ALLOCATOR_NEXT).set(value as f64);
}

pub(crate) fn set_nonce_pending_l1(value: u64) {
    metrics::gauge!(NONCE_PENDING_L1).set(value as f64);
}

/// Increment the regression sentinel for the defer-allocate invariant.
pub(crate) fn count_nonce_leak() {
    metrics::counter!(NONCE_LEAKS_TOTAL).increment(1);
}

/// Classify a `send_raw_transaction` failure string into a stable label
/// suitable for the `kind` field of [`L1_BROADCAST_FAILURES_TOTAL`].
/// Keeps cardinality bounded — any unclassified error collapses to `other`.
pub(crate) fn broadcast_failure_kind(err: &str) -> &'static str {
    if l1_rollup_client::is_nonce_too_low_error(err) {
        "nonce_too_low"
    } else {
        "other"
    }
}

/// Stable string label for [`crate::orchestrator::RevertKind`] — used as the
/// `kind` field of [`L1_DISPATCH_REJECTED_TOTAL`].
pub(crate) fn revert_kind_label(kind: crate::orchestrator::RevertKind) -> &'static str {
    match kind {
        crate::orchestrator::RevertKind::Oog => "oog",
        crate::orchestrator::RevertKind::Logic => "logic",
    }
}

fn wei_to_eth_f64(wei: U256) -> f64 {
    let wei_u128 = u128::try_from(wei).unwrap_or(u128::MAX);
    (wei_u128 as f64) / 1e18
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_failure_kind_detects_enclave_busy() {
        let err = eyre::eyre!(
            "proxy returned 500 Internal Server Error: \
             Enclave execution failed: Enclave error: enclave busy"
        );
        assert_eq!(sign_failure_kind(&err), "enclave_busy");
    }

    #[test]
    fn sign_failure_kind_falls_back_to_other() {
        let err = eyre::eyre!("proxy returned 502 Bad Gateway");
        assert_eq!(sign_failure_kind(&err), "other");
    }

    #[test]
    fn wei_to_eth_exact_for_one_eth() {
        let wei = U256::from(1_000_000_000_000_000_000u128);
        assert!((wei_to_eth_f64(wei) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn wei_to_eth_handles_typical_dispatch() {
        // 200_000 gas × 10 gwei = 2 × 10^15 wei = 0.002 ETH
        let wei = U256::from(2_000_000_000_000_000u128);
        assert!((wei_to_eth_f64(wei) - 0.002).abs() < 1e-12);
    }
}
