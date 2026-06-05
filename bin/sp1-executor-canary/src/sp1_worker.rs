//! SP1 worker loop: drains the bounded `ExecuteTask` channel, runs the
//! pinned `rsp-client` ELF through `ProverClient::light().execute()`,
//! cross-checks the public values against host-computed expected
//! values, and persists divergences to SQLite + Prometheus.
//!
//! Each worker holds its own `ProverClient::light()` instance for the
//! whole worker lifetime — one client setup per worker, regardless of
//! how many blocks it processes.
//!
//! On `kind == Unknown` (transient SP1-side failure not classified as a
//! deterministic STF/KZG/PublicValues divergence), the worker retries up
//! to `MAX_EXECUTE_ATTEMPTS` times before persisting a divergence row.
//! Deterministic divergences (STF mismatch, KZG mismatch, public-value
//! mismatch, deserialization failure) are NOT retried — the result is
//! a function of the inputs and would not change.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};

use rusqlite::Connection;
use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{
    completion_tracker::CompletionTracker,
    db::{append_divergence, write_last_canaried_block, DivergenceKind},
    types::ExecuteTask,
    verify::verify_public_values,
};

/// Maximum number of `client.execute()` attempts per block when the
/// observed error classifies as `DivergenceKind::Unknown`. Deterministic
/// divergences (STF/KZG/public-value mismatch, deserialization) are
/// **not** retried — the outcome is a pure function of the inputs.
const MAX_EXECUTE_ATTEMPTS: usize = 3;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run(
    worker_id: usize,
    rx: async_channel::Receiver<ExecuteTask>,
    elf_bytes: Arc<[u8]>,
    consumer_tip: Arc<AtomicU64>,
    tracker: Arc<Mutex<CompletionTracker>>,
    db: Arc<Mutex<Connection>>,
    shutdown: CancellationToken,
) {
    let client = ProverClient::builder().light().build().await;
    info!(event = "sp1_worker_started", worker_id, "sp1 worker ready");

    loop {
        let task = tokio::select! {
            _ = shutdown.cancelled() => break,
            r = rx.recv() => match r {
                Ok(t) => t,
                Err(_) => break,
            },
        };

        let block_number = task.block_number;
        // Each execute() consumes its `Elf` and `SP1Stdin`, so on retry
        // we have to rebuild both. `task.client_input` and
        // `task.blob_input` are immutable per-task so `write_slice` is
        // idempotent across attempts.
        let mut attempt: usize = 0;
        loop {
            if shutdown.is_cancelled() {
                break;
            }
            attempt += 1;

            let mut stdin = SP1Stdin::new();
            stdin.write_slice(&task.client_input);
            stdin.write_slice(&task.blob_input);
            stdin.write_slice(&task.cert_input);
            let elf = Elf::from(Arc::clone(&elf_bytes));

            let t_start = std::time::Instant::now();
            let result = client.execute(elf, stdin).await;
            let elapsed_ms = t_start.elapsed().as_millis() as u64;
            crate::metrics::observe_sp1_execute_duration(elapsed_ms);

            match result {
                Ok((public_values, _report)) => {
                    let bytes = public_values.as_slice();
                    match verify_public_values(bytes, &task.expected) {
                        Ok(()) => {
                            info!(
                                event = "canary_block_ok",
                                worker_id, block_number, elapsed_ms, attempt, "block canary ok"
                            );
                            crate::metrics::count_block_ok();
                        }
                        Err((kind, err)) => {
                            // Deterministic divergence — never retried.
                            warn!(
                                event = "canary_divergence",
                                worker_id,
                                block_number,
                                kind = kind.as_static_str(),
                                err = %err,
                                elapsed_ms,
                                attempt,
                                "public values mismatch"
                            );
                            append_divergence(&db, block_number, kind, &err);
                            crate::metrics::count_divergence(kind);
                        }
                    }
                    break;
                }
                Err(e) => {
                    let kind = classify_execute_error(&e);
                    if kind == DivergenceKind::Unknown && attempt < MAX_EXECUTE_ATTEMPTS {
                        warn!(
                            event = "canary_retry",
                            worker_id,
                            block_number,
                            attempt,
                            max_attempts = MAX_EXECUTE_ATTEMPTS,
                            err = %e,
                            elapsed_ms,
                            "transient sp1 execute failure — retrying"
                        );
                        continue;
                    }
                    warn!(
                        event = "canary_divergence",
                        worker_id,
                        block_number,
                        kind = kind.as_static_str(),
                        err = %e,
                        elapsed_ms,
                        attempt,
                        "sp1 execute failed"
                    );
                    append_divergence(&db, block_number, kind, &format!("{e}"));
                    crate::metrics::count_divergence(kind);
                    break;
                }
            }
        }

        // Strict-prefix watermark: advances only when no gaps remain
        // below `block_number`. Lock dropped before SQLite/Atomic
        // updates so workers don't serialize on slow IO.
        let new_watermark = {
            let mut t = tracker.lock().unwrap_or_else(|e| e.into_inner());
            t.mark_done(block_number)
        };
        if let Some(w) = new_watermark {
            write_last_canaried_block(&db, w);
            consumer_tip.fetch_max(w, Ordering::Relaxed);
            crate::metrics::set_last_block_canaried(w);
        }
    }

    info!(event = "sp1_worker_exited", worker_id, "sp1 worker exiting");
}

fn classify_execute_error<E: std::fmt::Display>(e: &E) -> DivergenceKind {
    let msg = format!("{e}");
    if msg.contains("STF execution failed") {
        DivergenceKind::StfFailed
    } else if msg.contains("DA/STF block_hash mismatch") {
        DivergenceKind::DaStfMismatch
    } else if msg.contains("KZG verification failed") {
        DivergenceKind::KzgVerifyFailed
    } else if msg.contains("KZG internal error") {
        DivergenceKind::KzgInternalError
    } else if msg.contains("blobs / commitments length mismatch") {
        DivergenceKind::BlobsCommitmentsLengthMismatch
    } else if msg.contains("blobs / proofs length mismatch") {
        DivergenceKind::BlobsProofsLengthMismatch
    } else if msg.contains("Invalid blob slice") {
        DivergenceKind::InvalidBlobSlice
    } else if msg.contains("Invalid commitment slice") {
        DivergenceKind::InvalidCommitmentSlice
    } else if msg.contains("Invalid proof slice") {
        DivergenceKind::InvalidProofSlice
    } else if msg.contains("deserialize") {
        DivergenceKind::DeserializationFailed
    } else {
        DivergenceKind::Unknown
    }
}
