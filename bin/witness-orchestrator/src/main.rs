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
//! | `WITNESS_RETENTION_BLOCKS` | `172800` | Cold store retention window in L2 blocks — blocks older than `tip - retention` are pruned on push. `0` disables retention (archive mode). |
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
//! | `orchestrator_last_batch_preconfirmed` | **gauge** | Index of the most recently L1-included `preconfirmBatch` observed via `BatchPreconfirmed` event. |
//! | `orchestrator_last_batch_preconfirmed_from_block` | **gauge** | `from_block` of the most recently L1-included batch. |
//! | `orchestrator_last_batch_preconfirmed_to_block` | **gauge** | `to_block` of the most recently L1-included batch. |
//! | `orchestrator_sign_block_execution_duration_seconds` | **histogram** | Per-attempt duration of `/sign-block-execution` HTTP call (seconds). |
//! | `orchestrator_sign_batch_root_duration_seconds` | **histogram** | Per-attempt duration of `/sign-batch-root` HTTP call (seconds). |
//! | `orchestrator_sign_failures_total` | **counter** | Sign-endpoint failures. Labels: `stage=block|batch`, `kind=enclave_busy|other`. |
//! | `orchestrator_l1_dispatch_rejected_total` | **counter** | `preconfirmBatch` txs that were mined with status=0 (on-chain revert). |
//! | `orchestrator_l1_broadcast_failures_total` | **counter** | `preconfirmBatch` broadcast attempts rejected by the L1 RPC before mempool admission. Labels: `kind=nonce_too_low|stuck_at_cap|other`. |
//! | `orchestrator_l1_dispatch_cost_eth` | **histogram** | Per-tx ETH cost of L1 `preconfirmBatch` (`gas_used` × `effective_gas_price` / 1e18). Cumulative sum available via the Prometheus-emitted `_sum` counterpart. |

mod blob_builder_mdbx;
mod block_response_cache;
mod challenge_db;
mod challenge_resolver;
mod db;
mod driver;
mod events_hash_reth;
mod hub;
mod l1_listener;
mod metrics;
mod orchestrator;
mod rbf;
mod types;

use std::{
    path::PathBuf,
    sync::{atomic::AtomicU64, Arc, Mutex},
    time::Duration,
};

use crate::{
    db::{Db, DbCommand},
    hub::{WitnessHub, DEFAULT_COLD_BATCH_SIZE},
};
use alloy_network::{Ethereum, EthereumWallet};
use alloy_primitives::Address;
use alloy_provider::{ProviderBuilder, RootProvider};
use alloy_signer_local::PrivateKeySigner;
use fluent_stf_primitives::fluent_chainspec;
use reth_chainspec::ChainSpec;
use reth_provider::BlockNumReader;
use reth_tasks::Runtime;
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
/// 512 GiB default MDBX geometry max size.
const DEFAULT_MDBX_MAX_SIZE: u64 = 512 * 1024 * 1024 * 1024;
/// Default cold-store retention window: 172 800 L2 blocks (~2 days at 1 s/block).
const DEFAULT_WITNESS_RETENTION_BLOCKS: u64 = 172_800;
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
    let witness_retention_blocks: u64 = std::env::var("WITNESS_RETENTION_BLOCKS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_WITNESS_RETENTION_BLOCKS);
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
    // +12.5% minimum).
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
        let db_startup = Db::open(&db_path).expect("Failed to open DB for startup");

        // DB-persisted start batch id takes precedence over the env var.
        // It is written by the BatchReverted handler after wiping all state,
        // so a restart re-resolves the L2 checkpoint from the reverted batch
        // instead of the stale env value that bootstrapped the deployment.
        let db_start_batch_id = db_startup.get_start_batch_id();
        let start_batch_id: Option<u64> = db_start_batch_id.or(env_start_batch_id);

        // Initial checkpoint is derived from the batches table — highest
        // to_block among rows with status >= Dispatched (preconfirm pipeline has
        // moved past these blocks).
        let mut initial_checkpoint = db_startup.highest_dispatched_to_block().unwrap_or(0);

        if let Some(batch_id) = start_batch_id {
            if initial_checkpoint == 0 {
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

                initial_checkpoint = l2_from_block.saturating_sub(1);

                // For env-var bootstrap we rewind l1_checkpoint one block
                // behind the committing event so the listener re-observes it.
                // For BatchReverted recovery the DB already holds the event
                // block — keep whichever is later.
                if db_start_batch_id.is_none() {
                    db_startup.save_l1_checkpoint(l1_event_block.saturating_sub(1));
                }

                // Clear the one-shot revert anchor so a manual env-var
                // restart later is not shadowed by a stale DB entry.
                if db_start_batch_id.is_some() {
                    db_startup.clear_start_batch_id();
                }

                info!(
                    batch_id,
                    l2_from_block, l1_event_block, "L2 start checkpoint resolved from L1"
                );
            } else {
                info!(
                    batch_id,
                    checkpoint = initial_checkpoint,
                    "L2 checkpoint already derivable from batches — skipping startup scan"
                );
            }
        }

        // Missing-block recovery is handled by the orchestrator's
        // `startup_recovery_feeder` task (priority-replay only the blocks
        // absent from `block_responses`); no checkpoint rollback here.
        let checkpoint = initial_checkpoint;
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
        witness_retention_blocks,
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

    // ── Orchestrator SQLite DB + writer actor ──────────────────────────────────
    //
    // Every mutating SQL operation in the orchestrator routes through `db_tx`
    // into the `run_db_writer` actor. Per-row commands coalesce into one
    // transaction per flush (size threshold or 100 ms timer); atomic multi-
    // statement commands run as their own transaction. Readers still hold the
    // `Arc<Mutex<Db>>` directly — reads are rare and serialize cheaply against
    // the writer actor's own Mutex scope.
    let db = Arc::new(Mutex::new(Db::open(&db_path).expect("Failed to open orchestrator DB")));
    let (db_tx, db_rx) = tokio::sync::mpsc::unbounded_channel::<DbCommand>();
    {
        let db = Arc::clone(&db);
        tasks.spawn(async move {
            db::run_db_writer(db_rx, db).await;
            ("db_writer", Ok::<(), eyre::Report>(()))
        });
    }

    // Shared watermark consumed by the driver's lookahead gate. Seeded from
    // the SQLite checkpoint resolved above; advanced by the orchestrator on
    // every block-result and finalization event.
    let orchestrator_tip = Arc::new(AtomicU64::new(orchestrator_checkpoint));

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
    let hub =
        Arc::new(WitnessHub::new(cold_file, witness_retention_blocks, DEFAULT_COLD_BATCH_SIZE)?);

    // ── Embedded forward-sync driver ─────────────────────────────────────────────
    let chain_spec: Arc<ChainSpec> = Arc::new(fluent_chainspec());
    let driver_rpc: RootProvider<Ethereum> = l2_provider.clone();
    let runtime = Runtime::with_existing_handle(Handle::current())
        .expect("failed to build reth_tasks::Runtime from current handle");
    let factory = driver::open_writable_factory::<driver::FluentMdbxNode>(
        &datadir,
        chain_spec.clone(),
        mdbx_max_size,
        runtime,
    )
    .expect("failed to open writable ProviderFactory");

    // Cold-aware auto-align. Must run AFTER heal_static_files_if_needed
    // (performed inside open_writable_factory) and BEFORE Driver::new, since
    // Driver::new snapshots `start_tip` once and never re-reads it. SQLite is
    // NOT reconciled here — operator's responsibility.
    //
    // Unwind to `cold_last` when cold trails MDBX. The re-witness branch falls
    // through to `execute_exex_with_block` on cold-miss, whose multiproof
    // construction is OOM-prone at depth, so we keep re-witness on the cold-hit
    // path and let the fresh-tip path rebuild below `cold_last` (allocation-
    // bounded per block).
    let unwind_target: Option<u64> = {
        let mdbx_tip = factory
            .best_block_number()
            .map_err(|e| eyre::eyre!("startup best_block_number: {e}"))?;
        let cold_last = hub
            .last_committed_block()
            .map_err(|e| eyre::eyre!("startup hub.last_committed_block: {e}"))?
            .unwrap_or(0);
        if mdbx_tip > cold_last {
            info!(
                cold_last,
                mdbx_tip,
                gap = mdbx_tip - cold_last,
                "Cold trails MDBX — auto-unwind to cold_last to keep re-witness on cold-hit path"
            );
            Some(cold_last)
        } else {
            None
        }
    };

    if let Some(target) = unwind_target {
        driver::unwind_to(factory.clone(), Arc::clone(&hub), target).await?;
    }

    let host_executor = Arc::new(EthHostExecutor::eth(chain_spec.clone(), None));

    let hub_for_shutdown = Arc::clone(&hub);
    let hub_for_feeder = Arc::clone(&hub);
    let driver = Arc::new(
        Driver::new(DriverConfig {
            factory,
            rpc: driver_rpc,
            host_executor,
            hub,
            chain_spec,
            witness_from_block,
            orchestrator_checkpoint,
            l2_safe_blocks,
        })
        .expect("Driver::new failed"),
    );

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
        http_client,
        l1_rollup_addr,
        nitro_verifier_addr,
        l1_provider: l1_write_provider,
        api_key,
        l1_signer,
        l1_signer_address,
        rbf_bump_interval,
        rbf_bump_percent,
        rbf_max_fee_per_gas_wei,
    };

    // Driver background loop is decoupled from the feeder so proxy
    // back-pressure never idles MDBX.
    {
        let driver = Arc::clone(&driver);
        let shutdown = shutdown.clone();
        tasks.spawn(async move {
            let r = driver.run_background_loop(shutdown).await;
            ("driver_loop", r)
        });
    }

    // Build and run the orchestrator. `new` performs every internal setup
    // (response cache, channels, nonce-allocator bootstrap, metric seeds);
    // `run` consumes self and supervises feeder + execution workers + per-
    // role workers (signer, dispatcher, finalization, router, challenge
    // resolver) until shutdown.
    let feeder_starting_block = orchestrator_checkpoint + 1;
    let orchestrator = orchestrator::Orchestrator::new(
        config,
        Arc::clone(&db),
        db_tx.clone(),
        driver,
        Arc::clone(&orchestrator_tip),
        l1_rx,
        shutdown.clone(),
        hub_for_feeder,
        feeder_starting_block,
    )
    .await;

    // Race the orchestrator against `tasks.join_next()` so that ANY background
    // task exiting first (signal handler, L1 listener, witness server, driver
    // loop) immediately cancels the root token. Catch-up is tracked separately
    // via `catchup_handle` because its successful completion is expected and
    // must not trigger shutdown.
    let mut exit_code = 0;
    let mut orchestrator_fut = std::pin::pin!(orchestrator.run());
    // Drop the outer `db_tx` so once the orchestrator exits and drops its
    // internal clone, the DB writer actor observes the close and drains
    // cleanly. Sign spawns hold their own `db_tx` clones transiently — those
    // drop when their tasks finish.
    drop(db_tx);

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
    const SHUTDOWN_DRAIN_TIMEOUT_SECS: u64 = 300;
    if tokio::time::timeout(Duration::from_secs(SHUTDOWN_DRAIN_TIMEOUT_SECS), drain_fut)
        .await
        .is_err()
    {
        tracing::error!(
            timeout_secs = SHUTDOWN_DRAIN_TIMEOUT_SECS,
            "Background tasks drain timed out — forcing shutdown"
        );
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
