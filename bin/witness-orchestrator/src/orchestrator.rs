//! Orchestrator: pulls witnesses from the embedded forward driver, dispatches
//! them to the Nitro proxy, and drives L1 batch signing + submission.
//!
//! # Architecture
//!
//! A persistent pool of `EXECUTION_WORKERS` tasks reads from a priority channel
//! pair (`high_rx` / `normal_rx`) via `biased` select, ensuring re-execution
//! after enclave key rotation takes precedence over fresh witnesses.
//!
//! Witnesses are **pulled** by a single feeder task that calls
//! [`Driver::try_take_new_block`] and forwards the result into `normal_tx`.
//! Back-pressure is natural: when workers are saturated, the feeder blocks on
//! `normal_tx.send().await`, which stops calling the driver, which idles.
//! The main select loop is drain-only — no branch performs an awaited send,
//! so the bounded channels cannot deadlock against it.
//!
//! On key rotation, blocks that need re-execution are fetched via
//! [`Driver::get_or_build_witness`] — cold-store hit is verbatim, cold miss
//! falls through to an MDBX-backed rebuild — and pushed onto the high-priority
//! queue independent of the feeder.

use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use async_channel::{Receiver as AsyncReceiver, Sender as AsyncSender};
use bytes::Bytes;
use tokio::{sync::mpsc, task::JoinSet, time::MissedTickBehavior};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn, Instrument};

use crate::{
    blob_builder_mdbx::build_blobs_from_mdbx,
    block_response_cache::ResponseCache,
    challenge_db, challenge_resolver,
    db::{self, AsyncOp, BatchStatus, ChallengeKind, Db, DbCommand, RbfResumeState},
    driver::Driver,
    hub::WitnessHub,
    l1_listener::L1Event,
    rbf,
    types::{
        EthExecutionResponse, InvalidSignaturesResponse, SignBatchRootRequest, SubmitBatchResponse,
    },
};
use l1_rollup_client::{nitro_verifier::is_key_registered, NonceAllocator};

use alloy_eips::BlockNumberOrTag;
use alloy_network::{Ethereum, EthereumWallet, TxSigner};
use alloy_primitives::{Address, Signature, B256};
use alloy_provider::{
    fillers::{
        BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller, WalletFiller,
    },
    Identity, Provider, RootProvider,
};

/// Concrete type of the L1 write provider built in `main`. Pinned to the
/// current alloy filler stack; a future alloy upgrade that changes the filler
/// chain will cause a compile error here and require updating the alias.
pub(crate) type L1WriteProvider = FillProvider<
    JoinFill<
        JoinFill<
            Identity,
            JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider,
    Ethereum,
>;

/// Maximum L1 blocks the RBF worker rebroadcasts at the fee cap before
/// undispatching so the dispatcher retries from scratch (re-estimate fees,
/// possibly higher cap by then). Without this, batch N stuck at-cap holds
/// the dispatch slot and N+1, N+2, … queue behind it indefinitely.
///
/// Chain-time, not wall-clock: RPC stalls / clock skew do not advance the
/// trigger, and an L1 finality stall naturally pauses it. ~12 s/block on
/// Ethereum mainnet → 25 blocks ≈ 5 min.
///
/// The challenge resolver clamps its per-row budget to
/// `min(STUCK_AT_CAP_BLOCKS, blocks_to_deadline)`.
pub(crate) const STUCK_AT_CAP_BLOCKS: u64 = 25;

/// Number of persistent execution workers sending blocks to the Nitro proxy.
const EXECUTION_WORKERS: usize = 8;

/// Bounded wait for workers to finish their in-flight HTTP calls on
/// shutdown. Longer than a typical request, shorter than a systemd
/// `TimeoutStopSec`.
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Return true at attempts 1, 2, 4, 8, 16, ... — exponential log thinning
/// so a prolonged L1 outage does not flood Loki while the orchestrator
/// polls forever waiting for the enclave key to be registered.
fn is_log_worthy(attempts: u64) -> bool {
    attempts > 0 && attempts.is_power_of_two()
}

/// zstd level for `/sign-block-execution` payload compression. Level 3 is the
/// default and a good size/CPU trade-off for online use (~3–10× on bincode
/// witness data; sub-100ms on multi-MB inputs).
#[cfg(feature = "zstd-block-payload")]
const ZSTD_COMPRESSION_LEVEL: i32 = 3;

#[derive(Clone)]
pub(crate) struct OrchestratorConfig {
    pub proxy_url: String,
    pub http_client: reqwest::Client,
    pub l1_rollup_addr: Address,
    pub nitro_verifier_addr: Address,
    pub l1_provider: L1WriteProvider,
    pub api_key: String,
    /// Held alongside `l1_provider` so the RBF worker can sign with an
    /// explicit nonce and fees, bypassing alloy's `NonceFiller` /
    /// `GasFiller`.
    pub l1_signer: Arc<dyn TxSigner<Signature> + Send + Sync>,
    pub l1_signer_address: Address,
    pub rbf_bump_interval: Duration,
    /// Must be `>= 13` to satisfy the EIP-1559 +12.5% replacement-tx
    /// minimum (20 by default).
    pub rbf_bump_percent: u32,
    /// Hitting this cap is a loud operator-attention event; the worker
    /// continues rebroadcasting at the cap.
    pub rbf_max_fee_per_gas_wei: u128,
}

/// All batch state lives in SQLite — `db` is the read path, `db_tx` is the
/// write path (every mutation goes through `run_db_writer`). Only the per-
/// block response hot cache (`ResponseCache`) is kept in-memory, behind the
/// same `std::sync::Mutex` discipline that keeps guards out of `.await`.
pub(crate) struct OrchestratorShared {
    pub(crate) config: OrchestratorConfig,
    pub(crate) db: Arc<std::sync::Mutex<Db>>,
    pub(crate) db_tx: mpsc::UnboundedSender<DbCommand>,
    pub(crate) cache: Arc<std::sync::Mutex<ResponseCache>>,
    pub(crate) nonce_allocator: Arc<NonceAllocator>,
    pub(crate) orchestrator_tip: Arc<AtomicU64>,
    /// Set by the signer on `InvalidSignatures` (key rotation detected),
    /// cleared by the spawned key-check task once the new key is on L1.
    /// The dispatcher skips broadcasting while this is `Some(_)`.
    pub(crate) pending_key_check: Arc<std::sync::Mutex<Option<Address>>>,
    /// Latest L1 block number observed by the L1 listener. Updated on every
    /// `Checkpoint` event the router processes. Read by the heartbeat worker
    /// to surface a whole-system snapshot in one log line; lock-free so
    /// heartbeat never depends on RPC liveness.
    pub(crate) last_seen_l1_block: Arc<AtomicU64>,
    high_tx: AsyncSender<ExecutionTask>,
    pub(crate) driver: Arc<Driver>,
    pub(crate) shutdown: CancellationToken,
}

struct ExecutionTask {
    block_number: u64,
    payload: Vec<u8>,
}

struct BlockResult {
    block_number: u64,
    response: EthExecutionResponse,
}

enum SignOutcome {
    Signed {
        response: SubmitBatchResponse,
    },
    /// Enclave key rotated; the listed blocks need re-execution against
    /// the new key.
    InvalidSignatures {
        invalid_blocks: Vec<u64>,
        enclave_address: Address,
    },
    TaskFailed,
}

/// Cheap classification of a reverted preconfirmBatch tx based on the
/// gasUsed/gasLimit ratio. A deepest-CALL out-of-gas burns ~all forwarded
/// gas and leaves only the EIP-150 1/64 reserve at the outer frame, so
/// `gasUsed` lands within ~5% of `gasLimit`. Anything well below that ratio
/// is a logic-revert (require failure with custom error data).
///
/// Used to decide retry policy: `Oog` → re-dispatch with inflated gas buffer
/// (estimate was too tight); `Logic` → undispatch + backoff (contract state
/// is in an unexpected shape, operator should inspect).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RevertKind {
    Oog,
    Logic,
}

impl RevertKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Oog => "oog",
            Self::Logic => "logic",
        }
    }
}

/// `gas_used / gas_limit >= 0.95` → Oog. Pulled out for unit testing.
pub(crate) fn classify_revert(gas_used: u64, gas_limit: u64) -> RevertKind {
    if gas_limit == 0 {
        return RevertKind::Logic;
    }
    if gas_used.saturating_mul(100) >= gas_limit.saturating_mul(95) {
        RevertKind::Oog
    } else {
        RevertKind::Logic
    }
}

enum ReceiptCheck {
    /// Receipt found with status=1. `finalized` reflects whether
    /// `l1_block <= finalized_block_number` at observation time —
    /// finality decisions are deferred to `apply_finalization_changes`.
    Found {
        finalized: bool,
    },
    Reverted {
        kind: RevertKind,
    },
    /// Receipt absent — implies the tx is no longer in the canonical
    /// chain (reorg) or the RPC is briefly inconsistent. Caller drives
    /// recovery by rolling status back to `Dispatched` so the dispatcher
    /// resumes RBF.
    Missing,
    CheckFailed,
}

enum FinalizationDone {
    Observed { observations: Vec<(u64, B256, ReceiptCheck)> },
    NoOp,
}

enum SignBatchError {
    InvalidSignatures { invalid_blocks: Vec<u64>, enclave_address: Address },
    Other(eyre::Report),
}

/// Worker pool task: high-before-normal `biased` select, retries
/// `/sign-block-execution` with exponential backoff. Cancel checked
/// between tasks only — never mid-HTTP-call.
#[allow(clippy::too_many_arguments)]
async fn execution_worker(
    _worker_id: usize,
    high_rx: AsyncReceiver<ExecutionTask>,
    normal_rx: AsyncReceiver<ExecutionTask>,
    result_tx: mpsc::Sender<BlockResult>,
    http_client: reqwest::Client,
    proxy_url: String,
    api_key: String,
    shutdown: CancellationToken,
) {
    loop {
        // biased: always drain high-priority (re-execution) before normal.
        // Cancel is checked ONLY between tasks — never mid-HTTP-call —
        // so an in-flight payload is either fully sent and answered, or
        // not started at all.
        let task = tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            Ok(t) = high_rx.recv() => t,
            Ok(t) = normal_rx.recv() => t,
            else => break,
        };

        let block_number = task.block_number;
        let process = async {
            #[cfg(feature = "zstd-block-payload")]
            let payload = {
                let uncompressed_len = task.payload.len();
                match zstd::encode_all(task.payload.as_slice(), ZSTD_COMPRESSION_LEVEL) {
                    Ok(compressed) => {
                        debug!(
                            uncompressed_len,
                            compressed_len = compressed.len(),
                            "Compressed block payload for /sign-block-execution"
                        );
                        Bytes::from(compressed)
                    }
                    Err(e) => {
                        error!(
                            err = %e,
                            "zstd compression failed — dropping task"
                        );
                        return false;
                    }
                }
            };
            #[cfg(not(feature = "zstd-block-payload"))]
            let payload = Bytes::from(task.payload);
            let mut backoff = Duration::from_millis(50);
            let mut attempts: u32 = 0;
            loop {
                attempts += 1;
                let t_start = std::time::Instant::now();
                match send_block_request(
                    &http_client,
                    &proxy_url,
                    &api_key,
                    block_number,
                    payload.clone(),
                )
                .await
                {
                    Ok(response) => {
                        let elapsed = t_start.elapsed();
                        metrics::histogram!(crate::metrics::SIGN_BLOCK_EXECUTION_DURATION)
                            .record(elapsed.as_secs_f64());
                        info!(
                            event = "sign_block_execution_done",
                            attempts,
                            duration_ms = elapsed.as_millis() as u64,
                            "sign-block-execution done"
                        );
                        if result_tx.send(BlockResult { block_number, response }).await.is_err() {
                            warn!(event = "result_channel_closed", "result channel closed");
                        }
                        return true;
                    }
                    Err(e) => {
                        metrics::histogram!(crate::metrics::SIGN_BLOCK_EXECUTION_DURATION)
                            .record(t_start.elapsed().as_secs_f64());
                        metrics::counter!(
                            crate::metrics::SIGN_FAILURES_TOTAL,
                            "stage" => "block",
                            "kind" => crate::metrics::sign_failure_kind(&e),
                        )
                        .increment(1);
                        warn!(
                            attempt = attempts,
                            err = %e,
                            "Execution failed, retrying"
                        );
                        tokio::select! {
                            _ = shutdown.cancelled() => return false,
                            _ = tokio::time::sleep(backoff) => {}
                        }
                        backoff = (backoff * 2).min(Duration::from_secs(2));
                    }
                }
            }
        };
        let span = tracing::info_span!("execute_block", block_number);
        if !process.instrument(span).await && shutdown.is_cancelled() {
            return;
        }
    }
}

/// Consume ready witnesses from the cold witness store in strict block
/// order and forward them to the execution worker pool via `normal_tx`.
///
/// **Invariant.** This is the ONLY producer for `normal_tx`; the key-rotation
/// replay path writes directly to the high-priority channel owned inside
/// `Orchestrator::run`. Back-pressure propagates naturally: when workers
/// saturate, `normal_tx.send().await` blocks the feeder — the driver's
/// background loop continues filling the hub up to the orchestrator_tip
/// lookahead cap.
///
/// Spawned inside `Orchestrator::run`; feeder exit cancels the orchestrator's
/// internal task race, which propagates back up to `main.rs`.
async fn feeder_loop(
    hub: Arc<WitnessHub>,
    normal_tx: AsyncSender<ExecutionTask>,
    cache: Arc<Mutex<ResponseCache>>,
    starting_block: u64,
    shutdown: CancellationToken,
) -> eyre::Result<()> {
    const FEEDER_IDLE: Duration = Duration::from_millis(100);
    let mut next_block = starting_block;
    loop {
        if shutdown.is_cancelled() {
            info!("Feeder: shutdown — exiting");
            break;
        }

        // Dedup: if the cache already has a response for this block (loaded
        // from `block_responses` at startup, or written by a prior tick),
        // skip the proxy round-trip and advance. `on_block_result` enforces
        // the gate if a dup slips through; this is an efficiency layer.
        if cache.lock().unwrap_or_else(|e| e.into_inner()).contains(next_block) {
            next_block += 1;
            continue;
        }

        match hub.get_witness(next_block).await {
            Some(req) => {
                let task = ExecutionTask { block_number: req.block_number, payload: req.payload };
                if normal_tx.send(task).await.is_err() {
                    warn!("Feeder: normal_tx closed — exiting");
                    break;
                }
                next_block += 1;
            }
            None => {
                // Driver has not yet committed block `next_block` — sleep and retry.
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(FEEDER_IDLE) => continue,
                }
            }
        }
    }
    info!("Feeder exited");
    Ok(())
}

/// Owns every internal piece of state assembled by `new`. `run` consumes the
/// struct, spawns the worker pool, the feeder, and the per-role workers, then
/// blocks until shutdown or any worker exits.
pub(crate) struct Orchestrator {
    shared: Arc<OrchestratorShared>,
    hub: Arc<WitnessHub>,
    feeder_starting_block: u64,
    initial_checkpoint: u64,
    high_rx: AsyncReceiver<ExecutionTask>,
    normal_tx: AsyncSender<ExecutionTask>,
    normal_rx: AsyncReceiver<ExecutionTask>,
    result_tx: mpsc::Sender<BlockResult>,
    result_rx: mpsc::Receiver<BlockResult>,
    l1_events: mpsc::Receiver<L1Event>,
}

impl Orchestrator {
    /// Build all internal state: `ResponseCache` (loaded from SQLite),
    /// `NonceAllocator` (bootstrapped from L1), execution-pool channels,
    /// metric seeds, and the shared context wired into every worker.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn new(
        config: OrchestratorConfig,
        db: Arc<Mutex<Db>>,
        db_tx: mpsc::UnboundedSender<DbCommand>,
        driver: Arc<Driver>,
        orchestrator_tip: Arc<AtomicU64>,
        l1_events: mpsc::Receiver<L1Event>,
        shutdown: CancellationToken,
        hub: Arc<WitnessHub>,
        feeder_starting_block: u64,
    ) -> Self {
        // Seed startup gauges from SQLite directly (no in-memory mirror).
        {
            let g = db.lock().unwrap_or_else(|e| e.into_inner());
            let checkpoint = g.highest_dispatched_to_block().unwrap_or(0);
            let preconfirmed_max: Option<(u64, u64, u64)> = g
                .find_highest_with_status_at_or_above(BatchStatus::Dispatched)
                .map(|b| (b.batch_index, b.from_block, b.to_block));
            let signed_max: Option<(u64, u64, u64)> =
                g.find_highest_signed().map(|b| (b.batch_index, b.from_block, b.to_block));
            crate::metrics::seed_gauges_on_startup(checkpoint, preconfirmed_max, signed_max);
        }

        let initial_last_batch_end: Option<u64> = {
            let g = db.lock().unwrap_or_else(|e| e.into_inner());
            g.highest_finalized_to_block()
        };

        // The single in-memory cache for `block_responses`; loaded from SQLite
        // on startup, written-through async, used by the feeder for dedup and
        // by the signer for batch-root assembly.
        let initial_responses: Vec<EthExecutionResponse> = {
            let g = db.lock().unwrap_or_else(|e| e.into_inner());
            g.load_responses()
        };
        let cache: Arc<Mutex<ResponseCache>> =
            Arc::new(Mutex::new(ResponseCache::new(initial_responses, db_tx.clone())));

        // Capacity tied to `EXECUTION_WORKERS`: each queued `ExecutionTask`
        // can hold a 30-80 MB payload, so larger buffers risk OOM.
        let (high_tx, high_rx) = async_channel::bounded::<ExecutionTask>(EXECUTION_WORKERS);
        let (normal_tx, normal_rx) = async_channel::bounded::<ExecutionTask>(EXECUTION_WORKERS * 2);
        let (result_tx, result_rx) = mpsc::channel::<BlockResult>(EXECUTION_WORKERS * 2);

        let initial_checkpoint = orchestrator_tip.load(Ordering::Relaxed);

        let stored_nonce_floor: Option<u64> = {
            let g = db.lock().unwrap_or_else(|e| e.into_inner());
            g.stored_nonce_floor()
        };
        let (allocator, pending) = NonceAllocator::bootstrap(
            &config.l1_provider,
            config.l1_signer_address,
            stored_nonce_floor,
        )
        .await
        .expect("NonceAllocator bootstrap failed — L1 RPC unreachable at startup");
        crate::metrics::set_nonce_pending_l1(pending);
        crate::metrics::set_nonce_allocator_next(allocator.peek());
        let nonce_allocator = Arc::new(allocator);

        let highest_responded: Option<u64> = {
            let g = db.lock().unwrap_or_else(|e| e.into_inner());
            g.highest_responded_block()
        };

        let target_tip = initial_checkpoint
            .max(initial_last_batch_end.unwrap_or(0))
            .max(highest_responded.unwrap_or(0));
        if target_tip > orchestrator_tip.load(Ordering::Relaxed) {
            orchestrator_tip.store(target_tip, Ordering::Relaxed);
        }

        let shared = Arc::new(OrchestratorShared {
            config,
            db,
            db_tx,
            cache,
            nonce_allocator,
            orchestrator_tip,
            pending_key_check: Arc::new(std::sync::Mutex::new(None)),
            last_seen_l1_block: Arc::new(AtomicU64::new(0)),
            high_tx,
            driver,
            shutdown,
        });

        Self {
            shared,
            hub,
            feeder_starting_block,
            initial_checkpoint,
            high_rx,
            normal_tx,
            normal_rx,
            result_tx,
            result_rx,
            l1_events,
        }
    }

    /// Spawn the execution-worker pool, the feeder, the startup-recovery
    /// task, and the five per-role workers, then block until shutdown or
    /// any supervised worker exits.
    pub(crate) async fn run(self) {
        let Self {
            shared,
            hub,
            feeder_starting_block,
            initial_checkpoint,
            high_rx,
            normal_tx,
            normal_rx,
            result_tx,
            result_rx,
            l1_events,
        } = self;

        let from_block = initial_checkpoint + 1;
        info!(from_block, "Orchestrator ready — awaiting witnesses");

        let mut workers: JoinSet<()> = JoinSet::new();
        for i in 0..EXECUTION_WORKERS {
            workers.spawn(
                execution_worker(
                    i,
                    high_rx.clone(),
                    normal_rx.clone(),
                    result_tx.clone(),
                    shared.config.http_client.clone(),
                    shared.config.proxy_url.clone(),
                    shared.config.api_key.clone(),
                    shared.shutdown.clone(),
                )
                .instrument(tracing::info_span!(
                    "execution_worker",
                    worker = "execution",
                    worker_id = i,
                )),
            );
        }
        info!(
            event = "execution_pool_started",
            workers = EXECUTION_WORKERS,
            "execution pool started"
        );

        // One-shot startup recovery: priority-replay blocks missing from
        // `block_responses` for any unsent batch. Run synchronously before
        // the JoinSet — putting it inside the JoinSet would tear the whole
        // process down on its (expected) successful exit, since
        // `tasks.join_next()` cancels the root token on any task exit.
        // L1 events buffer in `mpsc::channel(64)` with listener backpressure
        // for the duration, so events emitted during recovery are not lost.
        startup_recovery_feeder(
            Arc::clone(&shared.db),
            Arc::clone(&shared.driver),
            shared.high_tx.clone(),
            shared.shutdown.clone(),
        )
        .await;

        let mut tasks: JoinSet<&'static str> = JoinSet::new();
        {
            let hub = Arc::clone(&hub);
            let cache = Arc::clone(&shared.cache);
            let normal_tx = normal_tx.clone();
            let shutdown = shared.shutdown.clone();
            tasks.spawn(
                async move {
                    if let Err(e) =
                        feeder_loop(hub, normal_tx, cache, feeder_starting_block, shutdown).await
                    {
                        warn!(err = %e, "feeder exited with error");
                    }
                    "feeder"
                }
                .instrument(tracing::info_span!("feeder", worker = "feeder")),
            );
        }
        {
            let shared = Arc::clone(&shared);
            tasks.spawn(
                async move {
                    signer_worker(shared).await;
                    "signer_worker"
                }
                .instrument(tracing::info_span!("signer_worker", worker = "signer")),
            );
        }
        {
            let shared = Arc::clone(&shared);
            tasks.spawn(
                async move {
                    dispatcher_worker(shared).await;
                    "dispatcher_worker"
                }
                .instrument(tracing::info_span!("dispatcher_worker", worker = "dispatcher")),
            );
        }
        {
            let shared = Arc::clone(&shared);
            tasks.spawn(
                async move {
                    finalization_worker(shared).await;
                    "finalization_worker"
                }
                .instrument(tracing::info_span!("finalization_worker", worker = "finalization")),
            );
        }
        {
            let shared = Arc::clone(&shared);
            tasks.spawn(
                async move {
                    router(shared, l1_events, result_rx, initial_checkpoint).await;
                    "router"
                }
                .instrument(tracing::info_span!("router", worker = "router")),
            );
        }
        {
            let shared = Arc::clone(&shared);
            tasks.spawn(
                async move {
                    challenge_resolver::run(shared).await;
                    "challenge_resolver"
                }
                .instrument(tracing::info_span!(
                    "challenge_resolver",
                    worker = "challenge_resolver"
                )),
            );
        }
        {
            let shared = Arc::clone(&shared);
            tasks.spawn(
                async move {
                    heartbeat_loop(shared).await;
                    "heartbeat"
                }
                .instrument(tracing::info_span!("heartbeat", worker = "heartbeat")),
            );
        }

        // Any worker exit — clean or fatal — cancels the root token so the
        // rest drain together.
        tokio::select! {
            _ = shared.shutdown.cancelled() => {
                info!("Shutdown requested — draining orchestrator workers");
            }
            Some(join) = tasks.join_next() => {
                match join {
                    Ok(name) => info!(worker = name, "orchestrator worker exited"),
                    Err(e) => warn!(err = %e, "orchestrator worker join failed"),
                }
                shared.shutdown.cancel();
            }
        }

        while let Some(join) = tasks.join_next().await {
            match join {
                Ok(name) => info!(worker = name, "orchestrator worker drained"),
                Err(e) => warn!(err = %e, "orchestrator worker join failed during drain"),
            }
        }

        // Drop everything we still hold so the worker pool sees the channels
        // close and drains cleanly. Keep a handle to the response cache so
        // the post-drain shutdown log can report how many in-memory entries
        // are about to be dropped without persistence.
        info!("Closing worker task channels — draining execution workers");
        let cache_for_shutdown = Arc::clone(&shared.cache);
        drop(normal_tx);
        drop(result_tx);
        // `shared.high_tx` is the last live producer for `high_rx`; dropping
        // `shared` releases it.
        drop(shared);

        let drain = async {
            while let Some(res) = workers.join_next().await {
                if let Err(e) = res {
                    warn!(err = %e, "Worker panicked or was cancelled");
                }
            }
        };
        match tokio::time::timeout(SHUTDOWN_DRAIN_TIMEOUT, drain).await {
            Ok(()) => info!("All workers drained cleanly"),
            Err(_) => {
                warn!(
                    timeout_secs = SHUTDOWN_DRAIN_TIMEOUT.as_secs(),
                    "Shutdown drain deadline exceeded — aborting remaining workers"
                );
                workers.shutdown().await;
            }
        }
        let drained = cache_for_shutdown.lock().unwrap_or_else(|e| e.into_inner()).len();
        info!(
            event = "block_response_cache_shutdown_drained",
            drained, "block_response_cache drained on shutdown"
        );
        info!("Orchestrator::run exited");
    }
}

/// Narrow RPC surface for the finalization check. Blanket-impl'd for any
/// `alloy` `Provider` so production passes `&l1_provider`; tests stub it.
#[async_trait::async_trait]
pub(crate) trait FinalityRpc: Send + Sync {
    async fn finalized_block_number(&self) -> Option<u64>;
    async fn receipt_status(&self, tx_hash: B256) -> Result<Option<(bool, u64)>, String>;
    async fn tx_gas_limit(&self, tx_hash: B256) -> Result<Option<u64>, String>;
}

#[async_trait::async_trait]
impl<P: Provider + Send + Sync> FinalityRpc for P {
    async fn finalized_block_number(&self) -> Option<u64> {
        match self.get_block_by_number(BlockNumberOrTag::Finalized).await {
            Ok(Some(block)) => Some(block.header.number),
            Ok(None) => {
                warn!("Finalized block not available from RPC");
                None
            }
            Err(e) => {
                warn!(err = %e, "Failed to fetch finalized block");
                None
            }
        }
    }

    async fn receipt_status(&self, tx_hash: B256) -> Result<Option<(bool, u64)>, String> {
        match self.get_transaction_receipt(tx_hash).await {
            Ok(Some(r)) => Ok(Some((r.status(), r.gas_used))),
            Ok(None) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    async fn tx_gas_limit(&self, tx_hash: B256) -> Result<Option<u64>, String> {
        use alloy_consensus::Transaction as TransactionTrait;
        match self.get_transaction_by_hash(tx_hash).await {
            Ok(Some(tx)) => Ok(Some(tx.gas_limit())),
            Ok(None) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// `finalized_block = None` skips finality classification (challenges
/// have no per-row finality notion). `classify_revert_kind = false` skips
/// the gas-limit RPC; the returned `RevertKind::Logic` is a placeholder
/// that callers ignore.
async fn poll_receipts<Id: Copy + std::fmt::Debug>(
    provider: &dyn FinalityRpc,
    finalized_block: Option<u64>,
    snapshot: Vec<(Id, B256, u64)>,
    classify_revert_kind: bool,
) -> Vec<(Id, B256, ReceiptCheck)> {
    let mut out = Vec::with_capacity(snapshot.len());
    for (id, tx_hash, l1_block) in snapshot {
        let check = match provider.receipt_status(tx_hash).await {
            Ok(Some((true, _))) => ReceiptCheck::Found {
                finalized: finalized_block.map(|f| l1_block <= f).unwrap_or(false),
            },
            Ok(Some((false, gas_used))) => {
                let kind = if classify_revert_kind {
                    let gas_limit =
                        provider.tx_gas_limit(tx_hash).await.ok().flatten().unwrap_or(0);
                    classify_revert(gas_used, gas_limit)
                } else {
                    RevertKind::Logic
                };
                ReceiptCheck::Reverted { kind }
            }
            Ok(None) => ReceiptCheck::Missing,
            Err(e) => {
                warn!(?id, %tx_hash, err = %e, "Receipt check failed — will retry");
                ReceiptCheck::CheckFailed
            }
        };
        out.push((id, tx_hash, check));
    }
    out
}

/// Default heartbeat cadence. Operator override via `HEARTBEAT_INTERVAL_SECS`
/// env var. Long enough to avoid log spam in idle steady state, short enough
/// that a stuck pipeline produces a missing-heartbeat alert within a paging
/// SLO.
const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 300;

/// Periodic worker that emits one consolidated `info!(event = "heartbeat", ...)`
/// line every `HEARTBEAT_INTERVAL_SECS`. The line carries a snapshot of pipeline
/// state — batch counts grouped by status, active challenge count, MDBX tip,
/// and last L1 block observed by the listener — so an operator browsing
/// Graylog can confirm liveness and read the current pipeline shape from a
/// single log entry.
///
/// All inputs are in-process (SQLite under the existing DB Mutex, atomics on
/// `OrchestratorShared`); the worker never makes RPC calls. This keeps the
/// liveness signal independent of remote-system health, which is the property
/// operators rely on when external dependencies degrade.
async fn heartbeat_loop(shared: Arc<OrchestratorShared>) {
    let interval = std::env::var("HEARTBEAT_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(DEFAULT_HEARTBEAT_INTERVAL_SECS));

    loop {
        let (batch_counts, active_challenges) = {
            let g = shared.db.lock().unwrap_or_else(|e| e.into_inner());
            (g.batch_status_counts(), g.active_challenge_count())
        };
        let mdbx_tip = shared.driver.mdbx_tip().unwrap_or(0);
        let l1_tip = shared.last_seen_l1_block.load(Ordering::Relaxed);
        let orchestrator_tip = shared.orchestrator_tip.load(Ordering::Relaxed);

        let count_for = |s: BatchStatus| -> u64 {
            batch_counts.iter().find(|(t, _)| *t == s).map(|(_, c)| *c).unwrap_or(0)
        };

        info!(
            event = "heartbeat",
            committed = count_for(BatchStatus::Committed),
            accepted = count_for(BatchStatus::Accepted),
            dispatched = count_for(BatchStatus::Dispatched),
            preconfirmed = count_for(BatchStatus::Preconfirmed),
            finalized = count_for(BatchStatus::Finalized),
            active_challenges,
            mdbx_tip,
            l1_tip,
            orchestrator_tip,
            "heartbeat"
        );

        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shared.shutdown.cancelled() => break,
        }
    }
}

/// Pure-RPC half of the finalization + reorg check: takes a `dispatched`
/// snapshot and returns receipt observations without touching the DB.
/// Skips rows whose `l1_block IS NULL` (in-flight initial broadcast — the
/// dispatcher remains the sole observer until its first broadcast lands).
async fn poll_dispatched_receipts(
    provider: &dyn FinalityRpc,
    dispatched_snapshot: Vec<(u64, B256, u64)>,
) -> FinalizationDone {
    let Some(finalized_block) = provider.finalized_block_number().await else {
        return FinalizationDone::NoOp;
    };
    let candidates: Vec<(u64, B256, u64)> =
        dispatched_snapshot.into_iter().filter(|(_, _, l1_block)| *l1_block > 0).collect();
    if candidates.is_empty() {
        return FinalizationDone::NoOp;
    }
    let observations = poll_receipts(provider, Some(finalized_block), candidates, true).await;
    for (batch_index, tx_hash, check) in &observations {
        if let ReceiptCheck::Reverted { kind } = check {
            warn!(
                batch_index,
                %tx_hash,
                kind = kind.as_str(),
                "Finalization-ticker observed REVERTED preconfirmBatch"
            );
        }
    }
    FinalizationDone::Observed { observations }
}

#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip_all, fields(batch_index, from_block, to_block))]
async fn sign_batch_io(
    http_client: &reqwest::Client,
    proxy_url: &str,
    api_key: &str,
    batch_index: u64,
    from_block: u64,
    to_block: u64,
    responses: Vec<EthExecutionResponse>,
    driver: &Arc<Driver>,
    shutdown: &CancellationToken,
) -> SignOutcome {
    info!(batch_index, from_block, to_block, event = "batch_root_signing", "batch root signing");

    let blobs = {
        let mut backoff = Duration::from_secs(1);
        loop {
            match build_blobs_from_mdbx(driver, from_block, to_block)
                .await
            {
                Ok(Some(b)) => break b,
                // `Accepted` batches always have every block MDBX-committed (the
                // driver produced the witness that fed every response), so an
                // MDBX-tip-behind miss here is a real invariant violation.
                Ok(None) => error!(
                    batch_index,
                    from_block,
                    to_block,
                    backoff_secs = backoff.as_secs(),
                    "MDBX tip behind Accepted batch range — invariant violation; sign_batch_io waiting"
                ),
                Err(e) => warn!(
                    batch_index,
                    err = %e,
                    backoff_secs = backoff.as_secs(),
                    "MDBX blob construction failed — retrying"
                ),
            }
            tokio::select! {
                _ = tokio::time::sleep(backoff) => {}
                _ = shutdown.cancelled() => return SignOutcome::TaskFailed,
            }
            backoff = (backoff * 2).min(Duration::from_secs(30));
        }
    };

    info!(
        batch_index,
        event = "blobs_built",
        num_blobs = blobs.len(),
        "blobs built from l2 tx data"
    );

    let mut backoff = Duration::from_secs(1);
    loop {
        let t_start = std::time::Instant::now();
        match call_sign_batch_root(
            http_client,
            proxy_url,
            api_key,
            from_block,
            to_block,
            batch_index,
            &responses,
            &blobs,
        )
        .await
        {
            Ok(resp) => {
                let elapsed = t_start.elapsed();
                metrics::histogram!(crate::metrics::SIGN_BATCH_ROOT_DURATION)
                    .record(elapsed.as_secs_f64());
                info!(
                    batch_index,
                    event = "sign_batch_root_done",
                    duration_ms = elapsed.as_millis() as u64,
                    "batch root signed"
                );
                return SignOutcome::Signed { response: resp };
            }
            Err(SignBatchError::InvalidSignatures { invalid_blocks, enclave_address }) => {
                metrics::histogram!(crate::metrics::SIGN_BATCH_ROOT_DURATION)
                    .record(t_start.elapsed().as_secs_f64());
                warn!(
                    batch_index,
                    invalid_count = invalid_blocks.len(),
                    invalid_blocks_csv = %invalid_blocks
                        .iter()
                        .map(u64::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                    %enclave_address,
                    "Batch has stale signatures — key rotation detected"
                );
                return SignOutcome::InvalidSignatures { invalid_blocks, enclave_address };
            }
            Err(SignBatchError::Other(e)) => {
                metrics::histogram!(crate::metrics::SIGN_BATCH_ROOT_DURATION)
                    .record(t_start.elapsed().as_secs_f64());
                metrics::counter!(
                    crate::metrics::SIGN_FAILURES_TOTAL,
                    "stage" => "batch",
                    "kind" => crate::metrics::sign_failure_kind(&e),
                )
                .increment(1);
                warn!(
                    batch_index,
                    err = %e,
                    backoff_secs = backoff.as_secs(),
                    "sign-batch-root failed — retrying"
                );
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = shutdown.cancelled() => return SignOutcome::TaskFailed,
                }
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn call_sign_batch_root(
    http_client: &reqwest::Client,
    proxy_url: &str,
    api_key: &str,
    from_block: u64,
    to_block: u64,
    batch_index: u64,
    responses: &[EthExecutionResponse],
    blobs: &[Vec<u8>],
) -> Result<SubmitBatchResponse, SignBatchError> {
    let url = format!("{proxy_url}/sign-batch-root");

    let body = SignBatchRootRequest {
        from_block,
        to_block,
        batch_index,
        responses: responses.to_vec(),
        blobs: blobs.to_vec(),
    };

    let resp = http_client
        .post(&url)
        .timeout(Duration::from_secs(300))
        .header("x-api-key", api_key)
        .json(&body)
        .send()
        .await
        .map_err(|e| {
            use std::error::Error;
            let kind = if e.is_connect() {
                "connect"
            } else if e.is_timeout() {
                "timeout"
            } else if e.is_request() {
                "request"
            } else {
                "unknown"
            };
            let mut chain = format!("{e}");
            let mut source = e.source();
            while let Some(cause) = source {
                chain.push_str(&format!(" → {cause}"));
                source = cause.source();
            }
            SignBatchError::Other(eyre::eyre!("sign-batch-root failed ({kind}): {chain}"))
        })?;

    let status = resp.status();

    if status == reqwest::StatusCode::CONFLICT {
        let parsed: InvalidSignaturesResponse = resp
            .json()
            .await
            .map_err(|e| SignBatchError::Other(eyre::eyre!("Failed to parse 409: {e}")))?;
        return Err(SignBatchError::InvalidSignatures {
            invalid_blocks: parsed.invalid_blocks,
            enclave_address: parsed.enclave_address,
        });
    }

    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(SignBatchError::Other(eyre::eyre!("sign-batch-root returned {status}: {text}")));
    }

    resp.json::<SubmitBatchResponse>()
        .await
        .map_err(|e| SignBatchError::Other(eyre::eyre!("Failed to parse SubmitBatchResponse: {e}")))
}

async fn send_block_request(
    http_client: &reqwest::Client,
    proxy_url: &str,
    api_key: &str,
    block_number: u64,
    payload: Bytes,
) -> eyre::Result<EthExecutionResponse> {
    let url = format!("{proxy_url}/sign-block-execution");
    let req = http_client
        .post(&url)
        .timeout(Duration::from_secs(30))
        .header("content-type", "application/octet-stream")
        .header("x-block-number", block_number.to_string())
        .header("x-api-key", api_key)
        .body(payload);
    #[cfg(feature = "zstd-block-payload")]
    let req = req.header("content-encoding", "zstd");
    let resp = req.send().await.map_err(|e| eyre::eyre!("HTTP POST failed: {e}"))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_else(|_| "<unreadable>".into());
        return Err(eyre::eyre!("proxy returned {status}: {body}"));
    }

    resp.json::<EthExecutionResponse>()
        .await
        .map_err(|e| eyre::eyre!("Failed to parse response: {e}"))
}

const WORKER_TICK: Duration = Duration::from_secs(1);
const FINALIZATION_TICK: Duration = Duration::from_secs(30);

/// Capped at 5 minutes so a transient L1 outage cannot freeze dispatch
/// indefinitely.
#[derive(Default)]
pub(crate) struct DispatchBackoff {
    attempts: u32,
    next_allowed: Option<tokio::time::Instant>,
}

impl DispatchBackoff {
    pub(crate) fn apply(&mut self, reason: &'static str) {
        self.attempts += 1;
        let delay_secs = (10u64 * self.attempts as u64).min(300);
        self.next_allowed = Some(tokio::time::Instant::now() + Duration::from_secs(delay_secs));
        warn!(attempts = self.attempts, delay_secs, reason, "Dispatch backoff applied");
    }

    pub(crate) fn reset(&mut self) {
        self.attempts = 0;
        self.next_allowed = None;
    }

    pub(crate) fn is_blocking(&self) -> bool {
        match self.next_allowed {
            Some(deadline) => tokio::time::Instant::now() < deadline,
            None => false,
        }
    }
}

/// One-shot startup task: enumerate every block that is missing from
/// `block_responses` for any batch whose status is < Dispatched, build the
/// witness for it via the driver (cold-store hit or MDBX rebuild), and push
/// it onto the priority `high_tx` channel. The bounded channel provides
/// natural backpressure if the missing-block count is large.
async fn startup_recovery_feeder(
    db: Arc<Mutex<Db>>,
    driver: Arc<Driver>,
    high_tx: AsyncSender<ExecutionTask>,
    shutdown: CancellationToken,
) {
    let missing: Vec<u64> = {
        let g = db.lock().unwrap_or_else(|e| e.into_inner());
        g.missing_blocks_for_unsent_batches()
    };
    if missing.is_empty() {
        info!("Startup recovery: no missing blocks");
        return;
    }
    info!(count = missing.len(), "Startup recovery: priority-replaying missing blocks");
    for block_number in missing {
        if shutdown.is_cancelled() {
            return;
        }
        let payload = match driver.get_or_build_witness(block_number).await {
            Ok(Some(p)) => p,
            Ok(None) => {
                warn!(block_number, "Startup recovery: witness not available — skipping");
                continue;
            }
            Err(e) => {
                warn!(
                    block_number,
                    err = %e,
                    "Startup recovery: witness rebuild failed — skipping"
                );
                continue;
            }
        };
        if high_tx.send(ExecutionTask { block_number, payload }).await.is_err() {
            warn!("Startup recovery: high_tx closed — exiting");
            return;
        }
    }
    info!("Startup recovery: all missing blocks queued");
}

fn spawn_re_execution(shared: Arc<OrchestratorShared>, block_number: u64) {
    tokio::spawn(async move {
        let mut backoff = Duration::from_secs(1);
        let mut attempts: u64 = 0;
        loop {
            if shared.shutdown.is_cancelled() {
                return;
            }
            match shared.driver.get_or_build_witness(block_number).await {
                Ok(Some(payload)) => {
                    if shared.high_tx.send(ExecutionTask { block_number, payload }).await.is_err() {
                        warn!(block_number, "High-priority channel closed during re-execution");
                    }
                    return;
                }
                Ok(None) => {
                    attempts += 1;
                    if is_log_worthy(attempts) {
                        warn!(
                            block_number,
                            attempts,
                            "Re-execution: block not yet in MDBX and not cached — \
                             retrying with backoff"
                        );
                    }
                }
                Err(e) => {
                    attempts += 1;
                    if is_log_worthy(attempts) {
                        warn!(
                            block_number,
                            attempts,
                            err = %e,
                            "Re-execution: witness rebuild failed — retrying with backoff"
                        );
                    }
                }
            }
            tokio::select! {
                _ = shared.shutdown.cancelled() => return,
                _ = tokio::time::sleep(backoff) => {}
            }
            backoff = (backoff * 2).min(Duration::from_secs(60));
        }
    });
}

/// Polls L1 for the rotated key's registration; clears
/// `pending_key_check` on success so the dispatcher can resume.
fn spawn_key_check(shared: Arc<OrchestratorShared>, addr: Address) {
    tokio::spawn(async move {
        let mut attempts: u64 = 0;
        loop {
            if shared.shutdown.is_cancelled() {
                return;
            }
            let registered = is_key_registered(
                &shared.config.l1_provider,
                shared.config.nitro_verifier_addr,
                addr,
            )
            .await
            .unwrap_or(false);
            if registered {
                info!(%addr, attempts, "Enclave key confirmed on L1");
                let mut g = shared.pending_key_check.lock().unwrap_or_else(|e| e.into_inner());
                if *g == Some(addr) {
                    *g = None;
                }
                return;
            }
            attempts += 1;
            if is_log_worthy(attempts) {
                warn!(
                    %addr,
                    attempts,
                    "Enclave key still not registered — continuing to poll every 10s"
                );
            }
            tokio::select! {
                _ = shared.shutdown.cancelled() => return,
                _ = tokio::time::sleep(Duration::from_secs(10)) => {}
            }
        }
    });
}

#[cfg_attr(test, derive(Debug))]
enum DispatchTarget {
    /// A previous-lifetime broadcast left a row at `status='dispatched'`
    /// with `l1_block IS NULL` and full RBF state — resume its bump loop
    /// with the persisted nonce.
    ResumeInFlight {
        batch_index: u64,
        signature: Vec<u8>,
        resume: RbfResumeState,
    },
    Fresh {
        batch_index: u64,
        signature: Vec<u8>,
    },
    None,
}

fn pick_next_dispatch_target(db: &Db) -> DispatchTarget {
    if let Some((batch_index, signature, resume)) = db.first_inflight_resume() {
        return DispatchTarget::ResumeInFlight { batch_index, signature, resume };
    }
    if let Some(batch_index) = db.first_dispatchable() {
        if let Some(row) = db.find_batch(batch_index) {
            if let Some(sig) = row.signature {
                return DispatchTarget::Fresh { batch_index, signature: sig.signature };
            }
        }
    }
    DispatchTarget::None
}

/// One in-flight RBF lifecycle at a time. The "at most one fresh dispatch"
/// gate is what lets the resume scope return a single row.
async fn dispatcher_worker(shared: Arc<OrchestratorShared>) {
    let mut tick = tokio::time::interval(WORKER_TICK);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    tick.tick().await;
    let mut backoff = DispatchBackoff::default();

    loop {
        if shared.shutdown.is_cancelled() {
            break;
        }

        'work: {
            if backoff.is_blocking() {
                break 'work;
            }
            if shared.pending_key_check.lock().unwrap_or_else(|e| e.into_inner()).is_some() {
                break 'work;
            }

            let target = {
                let g = shared.db.lock().unwrap_or_else(|e| e.into_inner());
                pick_next_dispatch_target(&g)
            };

            match target {
                DispatchTarget::ResumeInFlight { batch_index, signature, resume } => {
                    info!(
                        batch_index,
                        nonce = resume.nonce,
                        tx_hash = %resume.tx_hash,
                        max_fee_per_gas = resume.max_fee_per_gas,
                        max_priority_fee_per_gas = resume.max_priority_fee_per_gas,
                        "RBF: resuming dispatched batch from persisted state"
                    );
                    rbf::run(&shared, batch_index, signature, Some(resume), &mut backoff).await;
                }
                DispatchTarget::Fresh { batch_index, signature } => {
                    rbf::run(&shared, batch_index, signature, None, &mut backoff).await;
                }
                DispatchTarget::None => {}
            }
        }

        tokio::select! {
            biased;
            _ = shared.shutdown.cancelled() => break,
            _ = tick.tick() => {}
        }
    }
    info!("dispatcher_worker exiting");
}

async fn signer_worker(shared: Arc<OrchestratorShared>) {
    let mut tick = tokio::time::interval(WORKER_TICK);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    tick.tick().await;

    loop {
        if shared.shutdown.is_cancelled() {
            break;
        }

        'work: {
            // Cache-completeness gate (not SQL): see `Db::first_signable`.
            let pick: Option<(u64, u64, u64, Vec<EthExecutionResponse>)> = {
                let g = shared.db.lock().unwrap_or_else(|e| e.into_inner());
                g.first_signable().and_then(|batch_index| {
                    let batch = g.find_batch(batch_index)?;
                    let from_block = batch.from_block;
                    let to_block = batch.to_block;
                    let cache = shared.cache.lock().unwrap_or_else(|e| e.into_inner());
                    if !cache.has_range(from_block, to_block) {
                        return None;
                    }
                    let responses = cache.get_range(from_block, to_block);
                    Some((batch_index, from_block, to_block, responses))
                })
            };

            let Some((batch_index, from_block, to_block, responses)) = pick else { break 'work };

            let outcome = sign_batch_io(
                &shared.config.http_client,
                &shared.config.proxy_url,
                &shared.config.api_key,
                batch_index,
                from_block,
                to_block,
                responses,
                &shared.driver,
                &shared.shutdown,
            )
            .await;

            match outcome {
                SignOutcome::Signed { response } => {
                    info!(
                        batch_index,
                        event = "batch_accepted_for_dispatch",
                        "batch accepted for dispatch"
                    );
                    if let Err(e) = db::record_signature(&shared.db_tx, batch_index, response).await
                    {
                        error!(batch_index, err = %e, "record_signature failed");
                        break 'work;
                    }
                    crate::metrics::set_last_batch_signed(batch_index, from_block, to_block);
                    let blocks: Vec<u64> = (from_block..=to_block).collect();
                    {
                        let mut c = shared.cache.lock().unwrap_or_else(|e| e.into_inner());
                        c.purge(&blocks);
                    }
                }
                SignOutcome::InvalidSignatures { invalid_blocks, enclave_address } => {
                    warn!(
                        batch_index,
                        invalid_count = invalid_blocks.len(),
                        %enclave_address,
                        "Key rotation detected — invalidating signature and re-executing"
                    );

                    if let Err(e) = db::invalidate_signature(&shared.db_tx, batch_index).await {
                        error!(batch_index, err = %e, "invalidate_signature failed");
                    }

                    {
                        let mut c = shared.cache.lock().unwrap_or_else(|e| e.into_inner());
                        c.purge(&invalid_blocks);
                    }

                    for &block_number in &invalid_blocks {
                        spawn_re_execution(Arc::clone(&shared), block_number);
                    }

                    {
                        let mut g =
                            shared.pending_key_check.lock().unwrap_or_else(|e| e.into_inner());
                        *g = Some(enclave_address);
                    }
                    spawn_key_check(Arc::clone(&shared), enclave_address);
                }
                SignOutcome::TaskFailed => {
                    error!(batch_index, "Sign task crashed — batch will be retried on next tick");
                }
            }
        }

        tokio::select! {
            biased;
            _ = shared.shutdown.cancelled() => break,
            _ = tick.tick() => {}
        }
    }
    info!("signer_worker exiting");
}

async fn finalization_worker(shared: Arc<OrchestratorShared>) {
    let mut tick = tokio::time::interval(FINALIZATION_TICK);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    tick.tick().await;

    loop {
        if shared.shutdown.is_cancelled() {
            break;
        }

        let batch_snapshot = {
            let g = shared.db.lock().unwrap_or_else(|e| e.into_inner());
            g.dispatched_for_finalization_check()
        };
        if !batch_snapshot.is_empty() {
            let done = poll_dispatched_receipts(&shared.config.l1_provider, batch_snapshot).await;
            apply_finalization_changes(
                &shared.db,
                &shared.db_tx,
                &shared.cache,
                &shared.orchestrator_tip,
                done,
            )
            .await;
        }

        // Refresh nonce_pending_l1 gauge so dashboard "drift" panels reflect
        // near-real-time state. NonceAllocator only writes the gauge on
        // bootstrap and after nonce-too-low resync; without this refresh the
        // value stays frozen for hours on a healthy pipeline. RPC errors are
        // non-fatal — gauge keeps its previous value.
        match shared
            .config
            .l1_provider
            .get_transaction_count(shared.config.l1_signer_address)
            .pending()
            .await
        {
            Ok(pending) => crate::metrics::set_nonce_pending_l1(pending),
            Err(e) => warn!(
                err = %e,
                event = "nonce_pending_l1_refresh_failed",
                "nonce_pending_l1 refresh failed"
            ),
        }

        // Reorg detection for dispatched challenge rows. The active worker
        // owns the in-flight RBF lifecycle (dispatched + l1_block IS NULL);
        // here we only watch rows that have already observed a receipt.
        let challenge_snapshot: Vec<(i64, B256, u64)> = {
            let guard = shared.db.lock().unwrap_or_else(|e| e.into_inner());
            guard.dispatched_challenges_with_l1_block()
        };
        if !challenge_snapshot.is_empty() {
            apply_challenge_reorg_check(
                &shared.config.l1_provider,
                &shared.db_tx,
                challenge_snapshot,
            )
            .await;
        }

        tokio::select! {
            biased;
            _ = shared.shutdown.cancelled() => break,
            _ = tick.tick() => {}
        }
    }
    info!("finalization_worker exiting");
}

/// For each dispatched challenge row that has previously observed a
/// receipt: re-check the receipt against L1. A missing receipt indicates
/// reorg — clear `l1_block` so the active worker re-broadcasts (using
/// the persisted `sp1_proof_bytes`, no re-prove). A revert indicates the
/// receipt-watcher missed the failure earlier — clear RBF state and
/// alert.
async fn apply_challenge_reorg_check(
    provider: &dyn FinalityRpc,
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    snapshot: Vec<(i64, B256, u64)>,
) {
    let observations = poll_receipts(provider, None, snapshot, false).await;
    for (challenge_id, tx_hash, check) in observations {
        match check {
            ReceiptCheck::Found { .. } => {} // challenge tx mined fine; nothing to do
            ReceiptCheck::Reverted { .. } => {
                crate::metrics::count_challenge_reverted_post_mine();
                warn!(
                    challenge_id,
                    %tx_hash,
                    "challenge tx receipt status=0 post-mine — clearing RBF state for retry"
                );
                if let Err(e) =
                    db::clear_challenge_rbf_state_post_mine_revert(db_tx, challenge_id).await
                {
                    error!(challenge_id, err = %e, "clear_challenge_rbf_state_post_mine_revert failed");
                }
            }
            ReceiptCheck::Missing => {
                crate::metrics::count_challenge_reorg_detected();
                warn!(
                    challenge_id,
                    %tx_hash,
                    "challenge tx receipt missing — suspecting reorg, clearing l1_block"
                );
                if let Err(e) = db::clear_challenge_l1_block(db_tx, challenge_id).await {
                    error!(challenge_id, err = %e, "clear_challenge_l1_block failed");
                }
            }
            ReceiptCheck::CheckFailed => {} // RPC flake — retry next tick
        }
    }
}

async fn apply_finalization_changes(
    db: &Arc<std::sync::Mutex<Db>>,
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    cache: &Arc<std::sync::Mutex<ResponseCache>>,
    orchestrator_tip: &Arc<AtomicU64>,
    done: FinalizationDone,
) {
    let FinalizationDone::Observed { observations } = done else {
        return;
    };
    for (batch_index, tx_hash, check) in observations {
        match check {
            ReceiptCheck::Found { finalized: true } => {
                let range = {
                    let g = db.lock().unwrap_or_else(|e| e.into_inner());
                    g.find_batch(batch_index).map(|b| (b.from_block, b.to_block))
                };
                if let Err(e) = db::observe_finalized(db_tx, batch_index).await {
                    error!(batch_index, err = %e, "observe_finalized failed");
                    continue;
                }
                let Some((from_block, to_block)) = range else { continue };
                {
                    let mut c = cache.lock().unwrap_or_else(|e| e.into_inner());
                    let blocks: Vec<u64> = (from_block..=to_block).collect();
                    c.purge(&blocks);
                }
                let current = orchestrator_tip.load(Ordering::Relaxed);
                if to_block > current {
                    orchestrator_tip.store(to_block, Ordering::Relaxed);
                }
                info!(
                    batch_index,
                    event = "batch_finalized",
                    %tx_hash,
                    to_block,
                    "batch finalized"
                );
            }
            ReceiptCheck::Found { finalized: false } => {
                // Receipt is observable but the L1 block is still in the
                // unfinalized window. No-op — wait for the next tick to
                // re-check finality.
            }
            ReceiptCheck::Reverted { kind } => {
                let still_ours = {
                    let g = db.lock().unwrap_or_else(|e| e.into_inner());
                    g.dispatched_tx_hash(batch_index) == Some(tx_hash)
                };
                if !still_ours {
                    info!(
                        batch_index,
                        %tx_hash,
                        "Stale ticker observation: dispatched tx_hash changed — skip"
                    );
                } else {
                    metrics::counter!(
                        crate::metrics::L1_DISPATCH_REJECTED_TOTAL,
                        "kind" => crate::metrics::revert_kind_label(kind),
                    )
                    .increment(1);
                    error!(
                        batch_index,
                        %tx_hash,
                        kind = kind.as_str(),
                        "Finalization-ticker rolling back reverted batch"
                    );
                    if let Err(e) = db::rollback_to_accepted(db_tx, batch_index).await {
                        error!(batch_index, err = %e, "rollback_to_accepted failed");
                    }
                }
            }
            ReceiptCheck::Missing => {
                // Reorg recovery: the L1 event was observed
                // (status=Preconfirmed + l1_block set) but the receipt is
                // gone. Roll status back to `Dispatched` + clear l1_block so
                // the dispatcher's `first_inflight_resume` resumes RBF
                // against the persisted nonce.
                let still_ours = {
                    let g = db.lock().unwrap_or_else(|e| e.into_inner());
                    g.dispatched_tx_hash(batch_index) == Some(tx_hash)
                };
                if !still_ours {
                    info!(
                        batch_index,
                        %tx_hash,
                        "Stale Missing observation: dispatched tx_hash changed — skip"
                    );
                    continue;
                }
                crate::metrics::count_batch_reorg_detected();
                warn!(
                    batch_index,
                    %tx_hash,
                    "Batch tx receipt missing — suspecting reorg, rolling back to Dispatched"
                );
                if let Err(e) = db::observe_reorg_to_dispatched(db_tx, batch_index).await {
                    error!(batch_index, err = %e, "observe_reorg_to_dispatched failed");
                }
            }
            ReceiptCheck::CheckFailed => {}
        }
    }
}

/// Owns the per-process `checkpoint` + `confirmed` state used to advance
/// the L2 watermark monotonically and triggers shutdown on `BatchReverted`.
async fn router(
    shared: Arc<OrchestratorShared>,
    mut l1_events: mpsc::Receiver<L1Event>,
    mut block_results: mpsc::Receiver<BlockResult>,
    initial_checkpoint: u64,
) {
    let mut checkpoint = initial_checkpoint;
    let mut confirmed: HashSet<u64> = HashSet::new();

    loop {
        tokio::select! {
            biased;
            _ = shared.shutdown.cancelled() => break,
            Some(event) = l1_events.recv() => {
                handle_l1_event(&shared, event).await;
            }
            Some(result) = block_results.recv() => {
                handle_block_result(&shared, result, &mut checkpoint, &mut confirmed).await;
            }
        }
    }
    info!("router exiting");
}

async fn handle_l1_event(shared: &OrchestratorShared, event: L1Event) {
    match event {
        L1Event::BatchCommitted { batch_index, from, to } => {
            if let Err(e) = db::observe_committed(&shared.db_tx, batch_index, from, to).await {
                error!(batch_index, err = %e, "observe_committed failed");
            }
        }
        L1Event::BatchSubmitted { batch_index } => {
            if let Err(e) = db::observe_submitted(&shared.db_tx, batch_index).await {
                error!(batch_index, err = %e, "observe_submitted failed");
            }
        }
        L1Event::BatchPreconfirmed { batch_index, tx_hash, l1_block } => {
            // Branching is by `signature.is_some()`: if we signed the batch
            // (we own it), preserve any RBF state we may have written.
            // Otherwise (external takeover edge case) clear nonce/fees and
            // adopt the event's tx_hash. The decision happens atomically
            // inside the writer actor — see `SyncOp::ObservePreconfirmed`.
            if let Err(e) =
                db::observe_preconfirmed(&shared.db_tx, batch_index, tx_hash, l1_block).await
            {
                error!(batch_index, err = %e, "observe_preconfirmed failed");
                return;
            }
            {
                let g = shared.db.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(batch) = g.find_batch(batch_index) {
                    crate::metrics::set_last_batch_preconfirmed(
                        batch_index,
                        batch.from_block,
                        batch.to_block,
                    );
                }
            }
        }
        L1Event::Checkpoint(l1_block) => {
            shared.last_seen_l1_block.store(l1_block, Ordering::Relaxed);
            if shared.db_tx.send(DbCommand::Async(AsyncOp::SaveL1Checkpoint(l1_block))).is_err() {
                warn!(l1_block, "save_l1_checkpoint: db writer channel closed");
            }
        }
        L1Event::BatchReverted { from_batch_index, l1_block } => {
            // Wipe persists the recovery anchors before shutdown so the
            // supervisor's restart can re-resolve the L2 checkpoint from
            // the reverted batch via `resolve_l2_start_checkpoint`.
            warn!(
                from_batch_index,
                l1_block,
                event = "batch_reverted",
                "batch reverted — wiping db and scheduling restart"
            );
            if let Err(e) = db::wipe_for_revert(&shared.db_tx, from_batch_index, l1_block).await {
                error!(from_batch_index, l1_block, err = %e, "wipe_for_revert failed");
            }
            shared.shutdown.cancel();
        }
        L1Event::BlockChallenged { batch_index, commitment } => {
            if let Err(e) = challenge_db::observe_block_challenged(
                &shared.db_tx,
                &shared.config.l1_provider,
                shared.config.l1_rollup_addr,
                batch_index,
                commitment,
                &shared.shutdown,
            )
            .await
            {
                // Only fires on shutdown — observe_block_challenged retries
                // L1 RPC failures internally.
                warn!(batch_index, %commitment, err = %e, "observe_block_challenged aborted (shutdown)");
            }
        }
        L1Event::BatchRootChallenged { batch_index } => {
            if let Err(e) = challenge_db::observe_batch_root_challenged(
                &shared.db_tx,
                &shared.config.l1_provider,
                shared.config.l1_rollup_addr,
                batch_index,
                &shared.shutdown,
            )
            .await
            {
                warn!(batch_index, err = %e, "observe_batch_root_challenged aborted (shutdown)");
            }
        }
        L1Event::ChallengeResolved { batch_index, commitment } => {
            if let Err(e) = challenge_db::observe_resolved(
                &shared.db,
                &shared.db_tx,
                ChallengeKind::Block,
                batch_index,
                Some(commitment),
            )
            .await
            {
                warn!(batch_index, %commitment, err = %e, "observe_resolved (block) failed");
            }
        }
        L1Event::BatchRootChallengeResolved { batch_index } => {
            if let Err(e) = challenge_db::observe_resolved(
                &shared.db,
                &shared.db_tx,
                ChallengeKind::BatchRoot,
                batch_index,
                None,
            )
            .await
            {
                warn!(batch_index, err = %e, "observe_resolved (batch_root) failed");
            }
        }
    }
}

async fn handle_block_result(
    shared: &OrchestratorShared,
    result: BlockResult,
    checkpoint: &mut u64,
    confirmed: &mut HashSet<u64>,
) {
    let block_number = result.block_number;

    if shared.cache.lock().unwrap_or_else(|e| e.into_inner()).contains(block_number) {
        return;
    }

    {
        let g = shared.db.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(lbe) = g.highest_finalized_to_block() {
            if block_number <= lbe {
                warn!(
                    block_number,
                    event = "block_result_dropped_finalized",
                    last_batch_to_block = lbe,
                    "ignoring block result: already finalized"
                );
                return;
            }
        }
    }

    {
        let mut c = shared.cache.lock().unwrap_or_else(|e| e.into_inner());
        c.insert(result.response);
    }

    metrics::gauge!(crate::metrics::LAST_BLOCK_EXECUTED).set(block_number as f64);

    confirmed.insert(block_number);
    while confirmed.contains(&(*checkpoint + 1)) {
        *checkpoint += 1;
        confirmed.remove(checkpoint);
    }
    let cp = *checkpoint;
    shared.orchestrator_tip.store(cp, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbf::bump_fees;

    #[test]
    fn classify_revert_above_95pct_is_oog() {
        assert_eq!(classify_revert(95_000, 100_000), RevertKind::Oog);
        assert_eq!(classify_revert(85_591, 86_476), RevertKind::Oog);
    }

    #[test]
    fn classify_revert_below_95pct_is_logic() {
        assert_eq!(classify_revert(50_000, 100_000), RevertKind::Logic);
        assert_eq!(classify_revert(30_000, 100_000), RevertKind::Logic);
        assert_eq!(classify_revert(94_999, 100_000), RevertKind::Logic);
    }

    #[test]
    fn classify_revert_zero_limit_is_logic() {
        assert_eq!(classify_revert(0, 0), RevertKind::Logic);
    }

    #[test]
    fn bump_fees_20_percent_both_fields() {
        let (fee, tip, clamped) = bump_fees(1_000_000_000, 100_000_000, 20, 500_000_000_000);
        assert_eq!(fee, 1_200_000_000);
        assert_eq!(tip, 120_000_000);
        assert!(!clamped);
    }

    #[test]
    fn bump_fees_clamps_at_cap() {
        let cap = 500_000_000_000u128;
        let (fee, tip, clamped) = bump_fees(500_000_000_000, 100_000_000, 20, cap);
        assert_eq!(fee, cap);
        assert!(tip <= fee);
        assert!(clamped);
    }

    #[test]
    fn bump_fees_tip_never_exceeds_fee() {
        let cap = 1_000_000_000u128;
        let (fee, tip, _) = bump_fees(900_000_000, 900_000_000, 20, cap);
        assert_eq!(fee, cap);
        assert!(tip <= fee);
    }

    #[test]
    fn bump_fees_eip1559_minimum_always_met() {
        let max_fee: u128 = 100_000_000_000;
        let tip: u128 = 10_000_000_000;
        let (fee_out, tip_out, _) = bump_fees(max_fee, tip, 20, u128::MAX);
        assert!(fee_out >= max_fee * 1125 / 1000);
        assert!(tip_out >= tip * 1125 / 1000);
    }
}
