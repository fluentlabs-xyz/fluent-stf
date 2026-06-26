//! Witness orchestrator sidecar binary.
//!
//! Runs an embedded forward-sync driver that re-executes Fluent L2 blocks,
//! produces witnesses in-process, and feeds them into the orchestrator loop
//! which dispatches to the Nitro proxy over HTTP and orchestrates L1 batch
//! signing and preconfirmation.
//!
//! ## Data flow
//!
//! ```text
//! L2 RPC ──▶ Driver (struct) ◀──pull── feeder ──▶ normal_tx ──▶ workers ──HTTP──▶ proxy
//!                   │                                                         │
//!                   └──▶ redb cold witness store             result_rx ◀──────┘
//! ```
//!
//! # Configuration (environment variables)
//!
//! | Variable | Default | Description |
//! |----------|---------|-------------|
//! | `RPC_URL` | — | L2 RPC URL — drives forward sync and blob construction |
//! | `DATADIR` | `./forward-driver` | Driver datadir (MDBX + static_files + RocksDB) |
//! | `WITNESS_COLD_FILE` | `<datadir>/cold.redb` | redb file for cold witness store |
//! | `MAX_COLD_BYTES` | `34359738368` (32 GiB) | Size cap for cold witness store |
//! | `WITNESS_RETENTION_BLOCKS` | `172800` | Cold store retention window in L2 blocks — blocks older than `tip - retention` are pruned on push. `0` disables retention (archive mode). |
//! | `WITNESS_HUB_LISTEN_ADDR` | `127.0.0.1:8090` | HTTP listen address of the witness-server that serves cold witnesses to external consumers (proxy). |
//! | `MDBX_MAX_SIZE` | `549755813888` (512 GiB) | MDBX max size |
//! | `PROXY_URL` | `http://127.0.0.1:8080` | Remote proxy base URL |
//! | `DB_PATH` | `./witness_orchestrator.db` | SQLite DB for crash recovery |
//! | `HTTP_TIMEOUT_SECS` | `120` | HTTP POST timeout (seconds) |
//! | `L1_RPC_URL` | — | L1 Ethereum RPC URL |
//! | `L1_ROLLUP_ADDR` | — | Rollup contract address on L1 |
//! | `L1_SUBMITTER_KEY` | — | Private key for signing `preconfirmBatch` txs |
//! | `L1_START_BATCH_ID` | — | If set (and no checkpoint in DB), scan L1 to derive L2 start checkpoint |
//! | `L1_ROLLUP_DEPLOY_BLOCK` | `0` | L1 block where Rollup contract was deployed (lower bound for event scans) |
//! | `API_KEY` | — | API key forwarded to the proxy |
//! | `PRUNE_FULL` | `false` | If `true`, prune MDBX/static-files using the same defaults as `reth --full` (sender_recovery=Full, receipts/account_history/storage_history distance=10064 blocks, bodies_history=Before(Paris)) |
//! | `FLUENT_METRICS_ADDR` | `0.0.0.0:9090` | HTTP listen address for the Prometheus `/metrics` endpoint. |
//!
//! # Metrics
//!
//! Mirrors the Go sequencer metric shape (see
//! `rollup-bridge-services/internal/services/sequencer/metrics.go`).
//! Scraped from `FLUENT_METRICS_ADDR` on `/metrics`.
//!
//! | Metric | Type | Description |
//! |--------|------|-------------|
//! | `orchestrator_last_block_witness_built` | **gauge** | Latest L2 block number for which a witness is available (built fresh or reused from cold store). |
//! | `orchestrator_last_block_executed` | **gauge** | Latest L2 block number executed by the proxy/enclave. |
//! | `orchestrator_last_block_signed` | **gauge** | Latest L2 block number included in a batch whose `/sign-batch-root` has succeeded (equals `last_batch_signed_to_block`). |
//! | `orchestrator_last_batch_signed` | **gauge** | Index of the most recently signed L1 batch (`/sign-batch-root`). |
//! | `orchestrator_last_batch_signed_from_block` | **gauge** | `from_block` of the most recently signed batch. |
//! | `orchestrator_last_batch_signed_to_block` | **gauge** | `to_block` of the most recently signed batch. |
//! | `orchestrator_last_batch_dispatched` | **gauge** | Index of the most recently L1-included `preconfirmBatch` (status=1). |
//! | `orchestrator_last_batch_dispatched_from_block` | **gauge** | `from_block` of the most recently L1-included batch. |
//! | `orchestrator_last_batch_dispatched_to_block` | **gauge** | `to_block` of the most recently L1-included batch. |
//! | `orchestrator_sign_block_execution_duration_seconds` | **histogram** | Per-attempt duration of `/sign-block-execution` HTTP call (seconds). |
//! | `orchestrator_sign_batch_root_duration_seconds` | **histogram** | Per-attempt duration of `/sign-batch-root` HTTP call (seconds). |
//! | `orchestrator_sign_failures_total` | **counter** | Sign-endpoint failures. Labels: `stage=block|batch`, `kind=enclave_busy|other`. |
//! | `orchestrator_l1_dispatch_rejected_total` | **counter** | `preconfirmBatch` txs that were mined with status=0 (on-chain revert). |
//! | `orchestrator_l1_broadcast_failures_total` | **counter** | `preconfirmBatch` broadcast attempts rejected by the L1 RPC before mempool admission. Labels: `kind=nonce_too_low|stuck_at_cap|other`. |
//! | `orchestrator_l1_dispatch_cost_eth` | **histogram** | Per-tx ETH cost of L1 `preconfirmBatch` (`gas_used` × `effective_gas_price` / 1e18). Cumulative sum available via the Prometheus-emitted `_sum` counterpart. |

mod accumulator;
mod db;
mod driver;
mod hub;
mod l1_listener;
mod metrics;
mod orchestrator;
mod types;
mod witness_server;

use std::{
    collections::HashSet,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Duration,
};

use crate::hub::{WitnessHub, DEFAULT_COLD_BATCH_SIZE};
use alloy_network::{Ethereum, EthereumWallet};
use alloy_primitives::Address;
use alloy_provider::{ProviderBuilder, RootProvider};
use alloy_signer_local::PrivateKeySigner;
use fluent_stf_primitives::fluent_chainspec;
use reth_chainspec::ChainSpec;
use reth_provider::BlockNumReader;
use reth_tasks::{RuntimeBuilder, RuntimeConfig, TokioConfig};
use rsp_host_executor::EthHostExecutor;
use tokio::runtime::Handle;
use tokio_util::sync::CancellationToken;
use tracing::info;

use driver::{Driver, DriverConfig};
use orchestrator::OrchestratorConfig;

const DEFAULT_PROXY_URL: &str = "http://127.0.0.1:8080";
const DEFAULT_DB_PATH: &str = "./witness_orchestrator.db";
const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 120;
const DEFAULT_DATADIR: &str = "./forward-driver";
/// 32 GiB default cap for cold witness storage.
const DEFAULT_MAX_COLD_BYTES: u64 = 32 * 1024 * 1024 * 1024;
/// 512 GiB default MDBX geometry max size.
const DEFAULT_MDBX_MAX_SIZE: u64 = 512 * 1024 * 1024 * 1024;
/// Default cold-store retention window: 172 800 L2 blocks (~2 days at 1 s/block).
const DEFAULT_WITNESS_RETENTION_BLOCKS: u64 = 172_800;
/// Default listen address for the witness HTTP server.
const DEFAULT_WITNESS_HUB_LISTEN_ADDR: &str = "127.0.0.1:8090";
/// Default listen address for the Prometheus `/metrics` HTTP server.
const DEFAULT_METRICS_LISTEN_ADDR: &str = "0.0.0.0:9090";

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Install Prometheus recorder before any spawn so early metric writes are
    // not lost to the noop recorder.
    let metrics_handle = Arc::new(metrics::install()?);
    let metrics_listen_addr =
        std::env::var("FLUENT_METRICS_ADDR").unwrap_or_else(|_| DEFAULT_METRICS_LISTEN_ADDR.into());

    let rpc_url = std::env::var("RPC_URL").expect("RPC_URL is required");
    let datadir =
        PathBuf::from(std::env::var("DATADIR").unwrap_or_else(|_| DEFAULT_DATADIR.into()));
    let cold_file = std::env::var("WITNESS_COLD_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| datadir.join("cold.redb"));
    let max_cold_bytes: u64 = std::env::var("MAX_COLD_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_COLD_BYTES);
    let witness_retention_blocks: u64 = std::env::var("WITNESS_RETENTION_BLOCKS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_WITNESS_RETENTION_BLOCKS);
    let witness_hub_listen_addr = std::env::var("WITNESS_HUB_LISTEN_ADDR")
        .unwrap_or_else(|_| DEFAULT_WITNESS_HUB_LISTEN_ADDR.into());
    let mdbx_max_size: u64 = std::env::var("MDBX_MAX_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MDBX_MAX_SIZE);

    let proxy_url = std::env::var("PROXY_URL").unwrap_or_else(|_| DEFAULT_PROXY_URL.into());
    let db_path =
        PathBuf::from(std::env::var("DB_PATH").unwrap_or_else(|_| DEFAULT_DB_PATH.into()));
    let http_timeout_secs: u64 = std::env::var("HTTP_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_HTTP_TIMEOUT_SECS);

    // L1 configuration
    let l1_rpc_url = std::env::var("L1_RPC_URL").expect("L1_RPC_URL is required");
    let l1_rollup_addr: Address = std::env::var("L1_ROLLUP_ADDR")
        .expect("L1_ROLLUP_ADDR is required")
        .parse()
        .expect("Invalid L1_ROLLUP_ADDR");
    let l1_submitter_key = std::env::var("L1_SUBMITTER_KEY").expect("L1_SUBMITTER_KEY is required");
    let nitro_verifier_addr: Address = fluent_stf_primitives::NITRO_VERIFIER_ADDR;
    let env_start_batch_id: Option<u64> =
        std::env::var("L1_START_BATCH_ID").ok().and_then(|s| s.parse().ok());
    let l1_deploy_block: u64 =
        std::env::var("L1_ROLLUP_DEPLOY_BLOCK").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    let api_key = std::env::var("API_KEY").expect("API_KEY is required");

    // RBF dispatch tuning: 15s cycle, +20% bump (safely above EIP-1559's
    // +12.5% minimum), 500 gwei cap.
    let rbf_bump_interval = Duration::from_secs(
        std::env::var("RBF_BUMP_INTERVAL_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(15),
    );
    let rbf_bump_percent: u32 =
        std::env::var("RBF_BUMP_PERCENT").ok().and_then(|s| s.parse().ok()).unwrap_or(20);
    let rbf_max_fee_per_gas_wei: u128 = std::env::var("RBF_MAX_FEE_PER_GAS_WEI")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(500_000_000_000u128);

    let l1_poll_interval_secs: u64 =
        std::env::var("L1_POLL_INTERVAL_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(60);
    let l1_safe_blocks: u64 =
        std::env::var("L1_SAFE_BLOCKS").ok().and_then(|s| s.parse().ok()).unwrap_or(7);
    let l2_safe_blocks: u64 =
        std::env::var("L2_SAFE_BLOCKS").ok().and_then(|s| s.parse().ok()).unwrap_or(10);

    // Optional destructive knob. Hard error on malformed value so a typo does
    // not silently skip the unwind (operator would then believe it ran).
    let unwind_to_block: Option<u64> = match std::env::var("UNWIND_TO_BLOCK") {
        Ok(s) => Some(s.parse().map_err(|e| eyre::eyre!("UNWIND_TO_BLOCK must be a u64: {e}"))?),
        Err(_) => None,
    };

    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(http_timeout_secs))
        .pool_max_idle_per_host(2)
        .build()
        .expect("failed to build HTTP client");

    // Build L1 provider for reading (events) — with retry layer for 429/5xx
    let l1_rpc_url_parsed: url::Url = l1_rpc_url.parse().expect("Invalid L1_RPC_URL");
    let l1_read_provider: RootProvider = rsp_provider::create_provider(l1_rpc_url_parsed.clone())
        .expect("failed to build L1 read provider");

    // Shared L2 provider: startup `lastBlockHash` resolve, embedded driver, blob builder.
    let l2_rpc_parsed: url::Url = rpc_url.parse().expect("Invalid RPC_URL");
    let l2_provider =
        rsp_provider::create_provider(l2_rpc_parsed).expect("failed to build L2 provider");

    // ── Startup: resolve L2 checkpoint from START_BATCH_ID ───────────────────────
    let (listener_from_block, witness_from_block, orchestrator_checkpoint): (u64, u64, u64) = {
        let db_startup = crate::db::Db::open(&db_path).expect("Failed to open DB for startup");

        // DB-persisted start batch id takes precedence over the env var.
        // It is written by the BatchReverted handler after wiping all state,
        // so a restart re-resolves the L2 checkpoint from the reverted batch
        // instead of the stale env value that bootstrapped the deployment.
        let db_start_batch_id = db_startup.get_start_batch_id();
        let start_batch_id: Option<u64> = db_start_batch_id.or(env_start_batch_id);

        if let Some(batch_id) = start_batch_id {
            if db_startup.get_checkpoint() == 0 {
                info!(
                    batch_id,
                    from_db = db_start_batch_id.is_some(),
                    "Resolving L2 start checkpoint from L1"
                );
                let (l2_from_block, l1_event_block, _num_blocks) =
                    l1_rollup_client::resolve_l2_start_checkpoint(
                        &l1_read_provider,
                        &l2_provider,
                        l1_rollup_addr,
                        batch_id,
                        l1_deploy_block,
                    )
                    .await
                    .expect("Fatal: failed to resolve L2 start checkpoint from L1");

                let l2_checkpoint = l2_from_block.saturating_sub(1);
                db_startup.save_checkpoint(l2_checkpoint);
                // For env-var bootstrap we rewind l1_checkpoint one block
                // behind the committing event so the listener re-observes it.
                // For BatchReverted recovery the DB already holds the event
                // block — keep whichever is later.
                if db_start_batch_id.is_none() {
                    db_startup.save_l1_checkpoint(l1_event_block.saturating_sub(1));
                }

                if db_startup.get_last_batch_end().is_none() {
                    db_startup.save_last_batch_end(l2_checkpoint);
                }

                // Clear the one-shot revert anchor so a manual env-var
                // restart later is not shadowed by a stale DB entry.
                if db_start_batch_id.is_some() {
                    db_startup.clear_start_batch_id();
                }

                info!(
                    batch_id,
                    l2_from_block,
                    l2_checkpoint,
                    l1_event_block,
                    "L2 start checkpoint resolved and saved to DB"
                );
            } else {
                info!(
                    batch_id,
                    checkpoint = db_startup.get_checkpoint(),
                    "L2 checkpoint already in DB — skipping startup scan"
                );
            }
        }

        // ── Startup checkpoint normalisation ───────────────────────────────────
        {
            let pending = db_startup.load_batches();
            let response_blocks: HashSet<u64> =
                db_startup.get_all_response_block_numbers().into_iter().collect();
            let signed_batch_indexes: HashSet<u64> =
                db_startup.load_batch_signature_indexes().into_iter().collect();
            let current_ckpt = db_startup.get_checkpoint();

            let result = normalize_startup_checkpoint(
                current_ckpt,
                &pending,
                &response_blocks,
                &signed_batch_indexes,
            );

            if let Some(gap) = result.earliest_gap {
                if !result.stale_signature_indexes.is_empty() {
                    info!(
                        current_ckpt,
                        earliest_gap = gap,
                        new_ckpt = result.new_ckpt,
                        gapped_batches = ?result.stale_signature_indexes,
                        "Startup gap recovery: rolling back checkpoint"
                    );
                    for idx in &result.stale_signature_indexes {
                        db_startup.delete_batch_signature(*idx);
                    }
                } else {
                    info!(
                        current_ckpt,
                        earliest_gap = gap,
                        "Startup gap detected but checkpoint already at or below rollback target"
                    );
                }
            } else {
                info!("Startup gap scan: no gaps detected");
            }

            if result.new_ckpt != current_ckpt {
                info!(current_ckpt, new_ckpt = result.new_ckpt, "Startup checkpoint normalised");
                db_startup.save_checkpoint(result.new_ckpt);
            } else {
                info!(current_ckpt, "Startup checkpoint unchanged");
            }
        }

        let checkpoint = db_startup.get_checkpoint();
        let witness_from = if checkpoint > 0 { checkpoint + 1 } else { 0 };

        let lfb = if let Some(ckpt) = db_startup.get_l1_checkpoint() {
            (ckpt + 1).max(l1_deploy_block)
        } else {
            l1_deploy_block
        };

        drop(db_startup);
        (lfb, witness_from, checkpoint)
    };

    info!(
        %rpc_url,
        ?datadir,
        ?cold_file,
        max_cold_bytes,
        witness_retention_blocks,
        %witness_hub_listen_addr,
        %proxy_url,
        ?db_path,
        http_timeout_secs,
        %l1_rollup_addr,
        %nitro_verifier_addr,
        listener_from_block,
        env_start_batch_id,
        l1_deploy_block,
        witness_from_block,
        l2_safe_blocks,
        unwind_to_block,
        "Starting witness orchestrator"
    );

    // Build L1 provider for writing (preconfirmBatch). Keep the signer as a
    // separate Arc'd handle so the RBF worker can sign bumped txs with an
    // explicit nonce + fees, bypassing alloy's NonceFiller / GasFiller.
    let signer: PrivateKeySigner = l1_submitter_key.parse().expect("Invalid L1_SUBMITTER_KEY");
    let l1_signer_address = signer.address();
    let l1_signer: Arc<dyn alloy_network::TxSigner<alloy_primitives::Signature> + Send + Sync> =
        Arc::new(signer.clone());
    let wallet = EthereumWallet::from(signer);
    let l1_write_provider: orchestrator::L1WriteProvider =
        ProviderBuilder::new().wallet(wallet).connect_http(l1_rpc_url_parsed);

    // Root shutdown token — cancelled on SIGTERM/SIGINT or on any
    // background task exit. Propagated into every spawned task so in-flight
    // work can drain cleanly instead of being abruptly dropped by runtime
    // teardown.
    let shutdown = CancellationToken::new();
    let mut tasks: tokio::task::JoinSet<(&'static str, eyre::Result<()>)> =
        tokio::task::JoinSet::new();

    // Signal handler. Also watches the shutdown token so an internal cancel
    // (e.g. BatchReverted handling) lets this task exit cleanly instead of
    // blocking the final JoinSet drain forever.
    {
        let shutdown = shutdown.clone();
        tasks.spawn(async move {
            let r = async {
                let mut sigterm =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .map_err(|e| eyre::eyre!("install SIGTERM: {e}"))?;
                tokio::select! {
                    _ = sigterm.recv() => {
                        info!("SIGTERM received — graceful shutdown");
                        shutdown.cancel();
                    }
                    _ = tokio::signal::ctrl_c() => {
                        info!("SIGINT received — graceful shutdown");
                        shutdown.cancel();
                    }
                    _ = shutdown.cancelled() => {
                        info!("Internal shutdown observed — exiting signal handler");
                    }
                }
                Ok::<(), eyre::Report>(())
            }
            .await;
            ("signal", r)
        });
    }

    // Metrics HTTP server — exposes `/metrics` on `FLUENT_METRICS_ADDR`.
    {
        let shutdown = shutdown.clone();
        let addr = metrics_listen_addr.clone();
        let handle = Arc::clone(&metrics_handle);
        tasks.spawn(async move {
            let r = metrics::run_server(addr, handle, shutdown).await;
            ("metrics_server", r)
        });
    }

    let l1_listened_l2_provider = l2_provider.clone();

    // Start L1 event listener
    let (l1_tx, l1_rx) = tokio::sync::mpsc::channel(64);
    {
        let shutdown = shutdown.clone();
        tasks.spawn(async move {
            let r = l1_listener::run(
                l1_read_provider,
                l1_listened_l2_provider,
                l1_rollup_addr,
                listener_from_block,
                l1_poll_interval_secs,
                l1_safe_blocks,
                l1_tx,
                shutdown,
            )
            .await;
            ("l1_listener", r)
        });
    }

    // Cold witness store. Owned by `Driver`; external consumers reach it
    // indirectly through `Driver::get_or_build_witness`, which also provides
    // the MDBX rebuild fallback on cold miss. Tip-following writes are
    // buffered in batches of `DEFAULT_COLD_BATCH_SIZE` to amortize redb fsync.
    let hub = Arc::new(WitnessHub::new(
        cold_file,
        max_cold_bytes,
        witness_retention_blocks,
        DEFAULT_COLD_BATCH_SIZE,
    )?);

    // ── Embedded forward-sync driver ─────────────────────────────────────────────
    let chain_spec: Arc<ChainSpec> = Arc::new(fluent_chainspec());
    let driver_rpc: RootProvider<Ethereum> = l2_provider.clone();
    let runtime = RuntimeBuilder::new(
        RuntimeConfig::default().with_tokio(TokioConfig::existing_handle(Handle::current())),
    )
    .build()
    .expect("failed to build reth_tasks::Runtime from current handle");
    let factory = driver::open_writable_factory::<driver::FluentMdbxNode>(
        &datadir,
        chain_spec.clone(),
        mdbx_max_size,
        runtime,
    )
    .expect("failed to open writable ProviderFactory");

    // One-shot unwind, if requested. Must run AFTER heal_static_files_if_needed
    // (performed inside open_writable_factory) and BEFORE Driver::new, since
    // Driver::new snapshots `start_tip` once and never re-reads it. SQLite is
    // NOT reconciled here — operator's responsibility.
    //
    // Priority:
    //   1. Explicit `UNWIND_TO_BLOCK` env — operator override, always wins.
    //   2. Auto-align to SQLite checkpoint — triggered when `orchestrator_checkpoint < mdbx_tip`,
    //   so MDBX never retains blocks past the last orchestrator-confirmed watermark. Rolls MDBX
    //   back to `orchestrator_checkpoint` (reth-CLI semantic: target is `orchestrator_checkpoint
    //   + 1`, so the checkpoint block itself is kept and everything above is dropped).
    let unwind_target: Option<u64> = if let Some(t) = unwind_to_block {
        Some(t)
    } else if orchestrator_checkpoint > 0 {
        let mdbx_tip = factory
            .best_block_number()
            .map_err(|e| eyre::eyre!("startup best_block_number: {e}"))?;
        if orchestrator_checkpoint < mdbx_tip {
            info!(
                orchestrator_checkpoint,
                mdbx_tip, "MDBX ahead of SQLite checkpoint — auto-unwind to checkpoint"
            );
            Some(orchestrator_checkpoint)
        } else {
            None
        }
    } else {
        None
    };

    if let Some(target) = unwind_target {
        if target < orchestrator_checkpoint {
            tracing::warn!(
                target,
                orchestrator_checkpoint,
                "UNWIND_TO_BLOCK below orchestrator SQLite checkpoint — SQLite state is \
                 NOT reconciled by this unwind; operator must manually reset the \
                 orchestrator DB if stale batch/response rows matter for recovery"
            );
        }
        driver::unwind_to(factory.clone(), Arc::clone(&hub), target).await?;
    }

    let host_executor = Arc::new(EthHostExecutor::eth(chain_spec.clone(), None));

    // TODO: re-enable pruner after adding runtime coupling between MDBX
    // prune floor and WITNESS_RETENTION_BLOCKS. The risk scenario: driver
    // runs far ahead while L1 is stalled (low ETH on submitter, rollup
    // contract frozen, etc.); pruner drops state for blocks that still
    // need re-witnessing on key rotation; re-exec fails with silent None
    // from `get_or_build_witness` and retries forever. Re-enabling needs:
    // (a) a runtime guard that stops the pruner when dispatch is lagging,
    // (b) an explicit StateAtBlockNotAvailable error instead of Ok(None)
    // from the driver's witness rebuild path. Until then — archive mode.
    let _ = std::env::var("PRUNE_FULL"); // swallow env so misconfig doesn't silently fail
    info!("Pruning disabled — archive mode");
    let pruner: Option<driver::DriverPruner> = None;

    let hub_for_shutdown = Arc::clone(&hub);
    let driver = Arc::new(
        Driver::new(DriverConfig {
            factory,
            rpc: driver_rpc,
            host_executor,
            hub,
            chain_spec,
            pruner,
            witness_from_block,
            orchestrator_checkpoint,
            l2_safe_blocks,
        })
        .expect("Driver::new failed"),
    );

    // Witness HTTP server — serves witnesses to the proxy (challenge/mock
    // endpoints). Cold-store hit is verbatim; cold miss falls through to an
    // MDBX-backed rebuild inside `Driver::get_or_build_witness`. Opens its
    // own read path into the cold `redb` file via the Arc it shares with the
    // driver — no cross-process lock conflict.
    {
        let driver = Arc::clone(&driver);
        let shutdown = shutdown.clone();
        let addr = witness_hub_listen_addr.clone();
        tasks.spawn(async move {
            let r = witness_server::run(addr, driver, shutdown).await;
            ("witness_server", r)
        });
    }

    // Catch-up runs as its own task so the orchestrator (L1 listener, signing,
    // dispatch) stays responsive while MDBX fast-forwards to witness_from_block.
    //
    // NOT added to `tasks` on purpose: this is a one-shot catch-up — successful
    // completion is expected (and happens instantly when MDBX is already past
    // `witness_from_block`). The JoinSet race below cancels the root token on
    // ANY task exit, so routing this through `tasks` would tear the whole
    // process down as soon as catch-up finished. On failure, we cancel the
    // root token here ourselves.
    let catchup_handle = {
        let driver = Arc::clone(&driver);
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            match driver.advance_to_witness_from_block(&shutdown).await {
                Ok(()) => info!("driver_catchup: completed"),
                Err(e) => {
                    tracing::error!(err = %e, "driver_catchup: fatal — cancelling shutdown");
                    shutdown.cancel();
                }
            }
        })
    };

    let config = OrchestratorConfig {
        proxy_url,
        db_path,
        http_client,
        l1_rollup_addr,
        nitro_verifier_addr,
        l1_provider: l1_write_provider,
        api_key,
        l2_provider,
        l1_signer,
        l1_signer_address,
        rbf_bump_interval,
        rbf_bump_percent,
        rbf_max_fee_per_gas_wei,
    };

    // Shared channel + dedup set between the feeder (driver pull) and the
    // orchestrator (worker pool consumer). Owned at the top level so the
    // feeder can be supervised via `tasks`.
    let (normal_tx, normal_rx) =
        async_channel::bounded::<orchestrator::ExecutionTask>(orchestrator::EXECUTION_WORKERS * 2);
    let known_responses: orchestrator::KnownResponses = Arc::new(RwLock::new(HashSet::new()));

    // Spawn the feeder into the top-level JoinSet so a feeder crash (driver
    // fatal, panic) cancels the root token via the `tasks.join_next()` race
    // below and shuts down the whole process cleanly.
    {
        let driver = Arc::clone(&driver);
        let normal_tx = normal_tx.clone();
        let known_responses = Arc::clone(&known_responses);
        let shutdown = shutdown.clone();
        tasks.spawn(async move {
            let r = orchestrator::feeder_loop(driver, normal_tx, known_responses, shutdown).await;
            ("feeder", r)
        });
    }

    // Orchestrator runs in the foreground. Race it against `tasks.join_next()`
    // so that ANY background task exiting first (signal handler, L1 listener,
    // witness server, feeder) immediately cancels the root token. Catch-up is
    // tracked separately via `catchup_handle` because its successful completion
    // is expected and must not trigger shutdown.
    let mut exit_code = 0;
    let mut orchestrator_fut = std::pin::pin!(orchestrator::run(
        config,
        driver,
        l1_rx,
        shutdown.clone(),
        normal_rx,
        Arc::clone(&known_responses),
    ));
    drop(normal_tx);

    tokio::select! {
        () = orchestrator_fut.as_mut() => {
            shutdown.cancel();
        }
        Some(join) = tasks.join_next() => {
            match join {
                Ok((name, Ok(()))) => info!(task = name, "background task exited cleanly"),
                Ok((name, Err(e))) => {
                    tracing::error!(task = name, err = %e, "background task exited with error");
                    exit_code = 1;
                }
                Err(e) => {
                    tracing::error!(err = %e, "background task join failed");
                    exit_code = 1;
                }
            }
            shutdown.cancel();
            orchestrator_fut.await;
        }
    }

    // Drain any remaining background tasks with a hard ceiling. Axum
    // `with_graceful_shutdown` will wait for in-flight requests to finish,
    // and a stuck TCP peer can hold that forever. Cap the drain so the
    // process exits even if a server hangs.
    let drain_fut = async {
        while let Some(join) = tasks.join_next().await {
            match join {
                Ok((name, Ok(()))) => info!(task = name, "background task exited cleanly"),
                Ok((name, Err(e))) => {
                    tracing::error!(task = name, err = %e, "background task exited with error");
                    exit_code = 1;
                }
                Err(e) => {
                    tracing::error!(err = %e, "background task join failed");
                    exit_code = 1;
                }
            }
        }
    };
    if tokio::time::timeout(Duration::from_secs(300), drain_fut).await.is_err() {
        tracing::error!("Background tasks drain timed out after 15s — forcing shutdown");
        exit_code = 1;
    }

    // Wait for catch-up to observe shutdown and exit. Aborts only if it's still
    // running — on normal exit it has already completed long ago.
    if let Err(e) = catchup_handle.await {
        if !e.is_cancelled() {
            tracing::error!(err = %e, "driver_catchup join failed");
            exit_code = 1;
        }
    }

    // Flush any buffered cold-witness entries before exit. On a clean shutdown
    // this makes `cold_last == mdbx_tip` so the next start needs no re-witness
    // gap-fill. A failure here is logged but does not change the exit code —
    // the re-witness fallback still handles any unflushed blocks on restart.
    if let Err(e) = hub_for_shutdown.flush_pending().await {
        tracing::error!(err = %e, "cold witness flush_pending failed at shutdown");
    }

    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

/// Pure result of the startup checkpoint walk.
///
/// Single pass over `pending` (ordered by `batch_index`):
/// - Signed batch: advance `new_ckpt` to its `to_block`.
/// - Unsigned batch: scan blocks in its range against `response_blocks`. On first missing block
///   `b`, set `new_ckpt = b - 1`, `earliest_gap = Some(b)`, mark signatures of later batches as
///   stale, and stop.
pub(crate) struct StartupCheckpointResult {
    pub(crate) new_ckpt: u64,
    pub(crate) stale_signature_indexes: Vec<u64>,
    /// First missing block number in an unsigned pending batch, if any.
    pub(crate) earliest_gap: Option<u64>,
}

pub(crate) fn normalize_startup_checkpoint(
    current_ckpt: u64,
    pending: &[accumulator::PendingBatch],
    response_blocks: &HashSet<u64>,
    signed_batch_indexes: &HashSet<u64>,
) -> StartupCheckpointResult {
    let mut new_ckpt = current_ckpt;
    let mut earliest_gap = None;
    let mut stale_signature_indexes = Vec::new();

    for (i, batch) in pending.iter().enumerate() {
        if signed_batch_indexes.contains(&batch.batch_index) {
            new_ckpt = batch.to_block;
            continue;
        }

        let mut batch_has_gap = false;
        for b in batch.from_block..=batch.to_block {
            if response_blocks.contains(&b) {
                new_ckpt = b;
                continue;
            }
            earliest_gap = Some(b);
            new_ckpt = b.saturating_sub(1);
            batch_has_gap = true;
            break;
        }

        if batch_has_gap {
            stale_signature_indexes = pending[i..]
                .iter()
                .filter(|b| signed_batch_indexes.contains(&b.batch_index))
                .map(|b| b.batch_index)
                .collect();
            break;
        }
    }

    StartupCheckpointResult { new_ckpt, stale_signature_indexes, earliest_gap }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accumulator::PendingBatch;

    fn batch(batch_index: u64, from: u64, to: u64) -> PendingBatch {
        PendingBatch { batch_index, from_block: from, to_block: to, blobs_accepted: true }
    }

    #[test]
    fn fallback_rolls_back_on_block_gap_below_current_ckpt() {
        // Fallback path (no signed batches): gap at block 50, ckpt=100.
        let pending = [batch(5, 40, 60)];
        let mut response_blocks = HashSet::new();
        for b in 40..=49 {
            response_blocks.insert(b);
        }
        let signed = HashSet::new();

        let r = normalize_startup_checkpoint(100, &pending, &response_blocks, &signed);

        assert_eq!(r.earliest_gap, Some(50));
        assert_eq!(r.new_ckpt, 49);
        assert!(r.stale_signature_indexes.is_empty());
    }

    #[test]
    fn fallback_walk_forward_advances_over_contiguous_responses() {
        // All blocks 11..=20 are in responses; ckpt starts at 10.
        let pending = [batch(1, 11, 20)];
        let mut response_blocks = HashSet::new();
        for b in 11..=20 {
            response_blocks.insert(b);
        }
        let signed = HashSet::new();

        let r = normalize_startup_checkpoint(10, &pending, &response_blocks, &signed);

        assert_eq!(r.new_ckpt, 20);
        assert!(r.earliest_gap.is_none());
        assert!(r.stale_signature_indexes.is_empty());
    }

    #[test]
    fn fallback_no_gap_keeps_current_ckpt() {
        let pending = [batch(1, 5, 10)];
        let mut response_blocks = HashSet::new();
        for b in 5..=10 {
            response_blocks.insert(b);
        }
        let signed = HashSet::new();

        let r = normalize_startup_checkpoint(10, &pending, &response_blocks, &signed);

        assert_eq!(r.new_ckpt, 10);
        assert!(r.earliest_gap.is_none());
    }

    #[test]
    fn fallback_gap_above_current_ckpt_advances_ckpt_to_gap_minus_one() {
        let pending = [batch(3, 40, 60)];
        let mut response_blocks = HashSet::new();
        for b in 40..=49 {
            response_blocks.insert(b);
        }
        let signed = HashSet::new();

        let r = normalize_startup_checkpoint(30, &pending, &response_blocks, &signed);

        assert_eq!(r.earliest_gap, Some(50));
        assert_eq!(r.new_ckpt, 49);
        assert!(r.stale_signature_indexes.is_empty());
    }

    #[test]
    fn fallback_walk_forward_after_rollback_does_not_jump_past_gap() {
        let pending = [batch(1, 10, 20), batch(2, 21, 30)];
        let mut response_blocks = HashSet::new();
        for b in 10..=14 {
            response_blocks.insert(b);
        }
        let signed = HashSet::new();

        let r = normalize_startup_checkpoint(25, &pending, &response_blocks, &signed);

        assert_eq!(r.earliest_gap, Some(15));
        assert_eq!(r.new_ckpt, 14);
        assert!(r.stale_signature_indexes.is_empty());
    }

    #[test]
    fn signed_single_batch_anchors_at_its_to_block() {
        let pending = [batch(7, 100, 110)];
        let response_blocks = HashSet::new();
        let signed: HashSet<u64> = [7].into_iter().collect();

        let r = normalize_startup_checkpoint(99, &pending, &response_blocks, &signed);

        assert_eq!(r.new_ckpt, 110);
        assert!(r.earliest_gap.is_none());
        assert!(r.stale_signature_indexes.is_empty());
    }

    #[test]
    fn signed_reports_block_gap_inside_next_pending_batch() {
        // Signed 7 (100..=110) + unsigned 8 (111..=120), no responses for 8.
        // Anchor at 110; earliest_gap = first missing block in batch 8 = 111.
        let pending = [batch(7, 100, 110), batch(8, 111, 120)];
        let response_blocks = HashSet::new();
        let signed: HashSet<u64> = [7].into_iter().collect();

        let r = normalize_startup_checkpoint(115, &pending, &response_blocks, &signed);

        assert_eq!(r.new_ckpt, 110);
        assert_eq!(r.earliest_gap, Some(111), "first missing block in batch N+1");
        assert!(r.stale_signature_indexes.is_empty());
    }

    #[test]
    fn signed_next_batch_fully_present_walks_through_responses() {
        // Signed 7 (100..=110), unsigned 8 (111..=120) fully in responses.
        // Walk-forward advances ckpt through batch 8's response blocks.
        let pending = [batch(7, 100, 110), batch(8, 111, 120)];
        let mut response_blocks = HashSet::new();
        for b in 111..=120 {
            response_blocks.insert(b);
        }
        let signed: HashSet<u64> = [7].into_iter().collect();

        let r = normalize_startup_checkpoint(105, &pending, &response_blocks, &signed);

        assert_eq!(r.new_ckpt, 120);
        assert!(r.earliest_gap.is_none());
    }

    #[test]
    fn signed_batch_index_gap_in_pending_is_not_detected() {
        // batch_signatures = {101, 102, 104}; batch 103 missing from pending.
        // Simple single-pass walk advances through all signed batches without
        // cross-checking batch-index contiguity — ckpt reaches last signed
        // batch's to_block, no gap reported.
        let pending = [batch(101, 100, 110), batch(102, 111, 120), batch(104, 131, 140)];
        let response_blocks = HashSet::new();
        let signed: HashSet<u64> = [101, 102, 104].into_iter().collect();

        let r = normalize_startup_checkpoint(140, &pending, &response_blocks, &signed);

        assert_eq!(r.new_ckpt, 140);
        assert!(r.stale_signature_indexes.is_empty());
        assert!(r.earliest_gap.is_none());
    }

    #[test]
    fn unsigned_batch_between_signed_reports_block_gap_and_marks_later_signed_stale() {
        // Signed {101, 102, 104}, unsigned 103 in pending with partial
        // responses 121..=125. Walk anchors to 102.to_block=120, advances
        // through 103's responses to 125, stops at missing 126. Signature of
        // 104 is stale since it sits past the gap.
        let pending = [
            batch(101, 100, 110),
            batch(102, 111, 120),
            batch(103, 121, 130),
            batch(104, 131, 140),
        ];
        let mut response_blocks = HashSet::new();
        for b in 121..=125 {
            response_blocks.insert(b);
        }
        let signed: HashSet<u64> = [101, 102, 104].into_iter().collect();

        let r = normalize_startup_checkpoint(140, &pending, &response_blocks, &signed);

        assert_eq!(r.new_ckpt, 125);
        assert_eq!(r.stale_signature_indexes, vec![104]);
        assert_eq!(r.earliest_gap, Some(126), "first missing block in batch 103");
    }

    #[test]
    fn signed_all_contiguous_anchors_at_max_no_gap() {
        let pending = [batch(101, 100, 110), batch(102, 111, 120), batch(103, 121, 130)];
        let response_blocks = HashSet::new();
        let signed: HashSet<u64> = [101, 102, 103].into_iter().collect();

        let r = normalize_startup_checkpoint(50, &pending, &response_blocks, &signed);

        assert_eq!(r.new_ckpt, 130);
        assert!(r.earliest_gap.is_none());
        assert!(r.stale_signature_indexes.is_empty());
    }

    #[test]
    fn signed_anchor_missing_from_pending_falls_through_to_fallback() {
        // Signed = {101} but batch 101 is not in pending (dispatched+removed).
        // Signed-first path can't anchor → fallback takes over.
        let pending: Vec<PendingBatch> = vec![];
        let response_blocks = HashSet::new();
        let signed: HashSet<u64> = [101].into_iter().collect();

        let r = normalize_startup_checkpoint(77, &pending, &response_blocks, &signed);

        assert_eq!(r.new_ckpt, 77, "fallback has no pending to scan, ckpt unchanged");
        assert!(r.earliest_gap.is_none());
        assert!(r.stale_signature_indexes.is_empty());
    }
}
