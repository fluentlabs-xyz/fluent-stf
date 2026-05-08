//! Prometheus metrics for the SP1 canary. Per workspace canon
//! (`gotchas.md`: "no inline string literals — register via
//! describe_*!"), every metric is a `pub const NAME: &str` registered
//! with `describe_*!` HELP, and label-bearing counters go through
//! helpers that take `&'static str` labels.

use std::sync::Arc;

use axum::{extract::State, response::IntoResponse, routing::get, Router};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::db::DivergenceKind;

pub(crate) const CANARY_LAST_BLOCK_CANARIED: &str = "canary_last_block_canaried";
pub(crate) const CANARY_BLOCKS_OK_TOTAL: &str = "canary_blocks_ok_total";
pub(crate) const CANARY_BLOCKS_SKIPPED_TOTAL: &str = "canary_blocks_skipped_total";
pub(crate) const CANARY_DIVERGENCE_TOTAL: &str = "canary_divergence_total";
pub(crate) const CANARY_DRIVER_MDBX_TIP: &str = "canary_driver_mdbx_tip";
pub(crate) const CANARY_SP1_EXECUTE_DURATION_SECS: &str = "canary_sp1_execute_duration_seconds";

/// Same exponential layout the orchestrator uses for SP1-touching
/// histograms — top buckets sized 2–4× the worst-case observed so a
/// cold-start outlier doesn't peg `histogram_quantile()` at the bucket
/// cap (per `general.md`: "Prometheus histogram top bucket silently
/// caps percentiles").
const SP1_DURATION_BUCKETS: &[f64] = &[
    0.5, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 512.0, 1024.0, 2048.0, 4096.0, 8192.0,
];

pub(crate) fn install() -> eyre::Result<PrometheusHandle> {
    let handle = PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Full(CANARY_SP1_EXECUTE_DURATION_SECS.to_string()),
            SP1_DURATION_BUCKETS,
        )
        .map_err(|e| eyre::eyre!("metrics buckets (sp1_execute_duration): {e}"))?
        .install_recorder()
        .map_err(|e| eyre::eyre!("install Prometheus recorder: {e}"))?;

    metrics::describe_gauge!(
        CANARY_LAST_BLOCK_CANARIED,
        "Highest fully-canaried block (strict prefix; advances only when all prior blocks complete)"
    );
    metrics::describe_counter!(
        CANARY_BLOCKS_OK_TOTAL,
        "Blocks for which `client.execute()` returned Ok AND public values matched expected"
    );
    metrics::describe_counter!(
        CANARY_BLOCKS_SKIPPED_TOTAL,
        "Empty blocks (zero transactions) skipped without running SP1 execute. \
         Toggled via CANARY_SKIP_EMPTY_BLOCKS env."
    );
    metrics::describe_counter!(
        CANARY_DIVERGENCE_TOTAL,
        "SP1 canary divergences. Labels: kind=<error/mismatch category>"
    );
    metrics::describe_gauge!(CANARY_DRIVER_MDBX_TIP, "Canary driver's MDBX tip (block number)");
    metrics::describe_histogram!(
        CANARY_SP1_EXECUTE_DURATION_SECS,
        "Per-block duration of `ProverClient::cpu().execute()` (seconds), recorded on every \
         outcome (Ok and Err)"
    );

    Ok(handle)
}

pub(crate) fn count_block_ok() {
    metrics::counter!(CANARY_BLOCKS_OK_TOTAL).increment(1);
}

pub(crate) fn count_block_skipped() {
    metrics::counter!(CANARY_BLOCKS_SKIPPED_TOTAL).increment(1);
}

pub(crate) fn count_divergence(kind: DivergenceKind) {
    metrics::counter!(CANARY_DIVERGENCE_TOTAL, "kind" => kind.as_static_str()).increment(1);
}

pub(crate) fn set_last_block_canaried(value: u64) {
    metrics::gauge!(CANARY_LAST_BLOCK_CANARIED).set(value as f64);
}

pub(crate) fn set_driver_mdbx_tip(value: u64) {
    metrics::gauge!(CANARY_DRIVER_MDBX_TIP).set(value as f64);
}

pub(crate) fn observe_sp1_execute_duration(elapsed_ms: u64) {
    metrics::histogram!(CANARY_SP1_EXECUTE_DURATION_SECS).record(elapsed_ms as f64 / 1000.0);
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
    info!(listen_addr, "Canary metrics HTTP server listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(async move { shutdown.cancelled().await })
        .await
        .map_err(|e| eyre::eyre!("metrics server error: {e}"))
}

async fn render_metrics(State(handle): State<Arc<PrometheusHandle>>) -> impl IntoResponse {
    handle.render()
}
