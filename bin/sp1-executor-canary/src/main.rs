//! sp1-executor-canary — silent canary that re-runs production L2 blocks
//! through the pinned `rsp-client` SP1 ELF (CPU emulation, no proof) and
//! cross-checks the committed public values against host-computed
//! expected values. On panic / public-values mismatch / executor error,
//! appends a row to the local SQLite divergences table and increments a
//! Prometheus counter; the sidecar continues running.
//!
//! See `README.md` and `.env.example` for env-var configuration.

mod completion_tracker;
mod db;
mod metrics;
mod sp1_worker;
mod types;
mod verify;
mod window_worker;

use std::{
    path::PathBuf,
    sync::{atomic::AtomicU64, Arc, Mutex},
};

use alloy_provider::{Provider, RootProvider};
use completion_tracker::CompletionTracker;
use fluent_stf_primitives::fluent_chainspec;
use reth_chainspec::ChainSpec;
use reth_provider::BlockNumReader;
use reth_tasks::Runtime;
use rsp_host_executor::EthHostExecutor;
use tokio::runtime::Handle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use witness_orchestrator::{
    driver::{open_writable_factory, Driver, DriverConfig, FluentMdbxNode},
    hub::{WitnessHub, DEFAULT_COLD_BATCH_SIZE},
};

const DEFAULT_DATADIR: &str = "./canary-driver";
const DEFAULT_DB_PATH: &str = "./sp1_canary.db";
const DEFAULT_MDBX_MAX_SIZE: u64 = 512 * 1024 * 1024 * 1024;
const DEFAULT_WITNESS_RETENTION_BLOCKS: u64 = 172_800;
const DEFAULT_METRICS_LISTEN_ADDR: &str = "0.0.0.0:9091";
const DEFAULT_WINDOW_SIZE: u64 = 1024;
const DEFAULT_SP1_WORKERS: usize = 2;
const DEFAULT_MAX_LOOKAHEAD_BLOCKS: u64 = 4096;
const DEFAULT_TRACING_DIRECTIVES: &str = "info,\
    alloy=warn,\
    reth=warn,\
    hyper=warn,\
    hyper_util=warn,\
    reqwest=warn,\
    tower=warn,\
    h2=warn";

fn init_tracing() {
    use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(DEFAULT_TRACING_DIRECTIVES));

    let format = std::env::var("LOG_FORMAT").unwrap_or_else(|_| "pretty".into());
    let deploy_env = std::env::var("DEPLOY_ENV").unwrap_or_else(|_| "unknown".into());

    match format.as_str() {
        "json" => {
            let layer = tracing_format::json_layer(
                "sp1-executor-canary",
                env!("CARGO_PKG_VERSION"),
                deploy_env,
            );
            tracing_subscriber::registry().with(env_filter).with(layer).init();
        }
        _ => {
            tracing_subscriber::registry().with(env_filter).with(fmt::layer()).init();
        }
    }
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    init_tracing();

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
    let db_path =
        PathBuf::from(std::env::var("DB_PATH").unwrap_or_else(|_| DEFAULT_DB_PATH.into()));
    let l2_safe_blocks: u64 =
        std::env::var("L2_SAFE_BLOCKS").ok().and_then(|s| s.parse().ok()).unwrap_or(10);
    let window_size: u64 = std::env::var("CANARY_WINDOW_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_WINDOW_SIZE);
    let sp1_workers: usize = std::env::var("SP1_WORKERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_SP1_WORKERS);
    let max_lookahead_blocks: u64 = std::env::var("MAX_LOOKAHEAD_BLOCKS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_LOOKAHEAD_BLOCKS);
    let skip_empty_blocks: bool = std::env::var("CANARY_SKIP_EMPTY_BLOCKS")
        .map(|s| matches!(s.as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);
    let elf_path = std::env::var("SP1_ELF_PATH").expect("SP1_ELF_PATH is required");
    let env_witness_from_block: Option<u64> =
        std::env::var("WITNESS_FROM_BLOCK").ok().and_then(|s| s.parse().ok());

    // The driver gates production at `consumer_tip + max_lookahead_blocks`,
    // and the window worker waits for `mdbx_tip >= window_end`. If the
    // cap is smaller than the window, the driver never fills a single
    // window → window_worker waits forever → consumer_tip never advances
    // → driver stays gated. Fail-fast at startup.
    eyre::ensure!(
        max_lookahead_blocks >= window_size,
        "MAX_LOOKAHEAD_BLOCKS ({max_lookahead_blocks}) must be >= CANARY_WINDOW_SIZE \
         ({window_size}) — otherwise driver/window-worker deadlock at startup"
    );

    let elf_bytes: Arc<[u8]> =
        std::fs::read(&elf_path).map_err(|e| eyre::eyre!("read SP1 ELF {elf_path}: {e}"))?.into();
    info!(event = "elf_loaded", path = %elf_path, bytes = elf_bytes.len(), "SP1 ELF loaded");

    let db_conn = db::open(&db_path)?;
    let last_canaried = db::read_last_canaried_block(&db_conn)?;
    let db = Arc::new(Mutex::new(db_conn));

    let l2_provider: RootProvider = rsp_provider::create_provider(rpc_url.parse()?)?;

    let chain_spec: Arc<ChainSpec> = Arc::new(fluent_chainspec());
    let runtime = Runtime::with_existing_handle(Handle::current())?;
    let factory = open_writable_factory::<FluentMdbxNode>(
        &datadir,
        chain_spec.clone(),
        mdbx_max_size,
        runtime,
    )?;
    // Read MDBX tip BEFORE Driver::new so we can fall back to it when
    // both `WITNESS_FROM_BLOCK` env and SQLite are empty. `0` means
    // truly fresh datadir — no orchestrator reuse, no prior canary.
    let mdbx_tip =
        factory.best_block_number().map_err(|e| eyre::eyre!("startup best_block_number: {e}"))?;

    // Resolve start cursor (priority order):
    //   1. explicit env (operator override),
    //   2. SQLite resume — last canaried block + 1,
    //   3. MDBX tip + 1 if datadir non-empty (typical case: canary points at orchestrator's
    //      existing datadir or resumes a prior canary whose SQLite was wiped),
    //   4. L2 RPC tip on truly fresh datadir (skip ancient history).
    let start_cursor: u64 = match (env_witness_from_block, last_canaried) {
        (Some(env_v), _) => env_v,
        (None, Some(db_v)) => db_v + 1,
        (None, None) => {
            if mdbx_tip > 0 {
                mdbx_tip + 1
            } else {
                l2_provider.get_block_number().await?
            }
        }
    };
    info!(
        event = "start_cursor_resolved",
        start_cursor,
        env_witness_from_block,
        last_canaried,
        mdbx_tip,
        "canary start cursor resolved"
    );

    let hub =
        Arc::new(WitnessHub::new(cold_file, witness_retention_blocks, DEFAULT_COLD_BATCH_SIZE)?);
    if mdbx_tip >= start_cursor {
        info!(
            event = "canary_auto_unwind",
            mdbx_tip,
            start_cursor,
            blocks_to_remove = mdbx_tip - (start_cursor - 1),
            "MDBX tip ahead of start_cursor — unwinding for fresh-witness path"
        );
        witness_orchestrator::driver::unwind_to(factory.clone(), Arc::clone(&hub), start_cursor)
            .await?;
    }

    let host_executor = Arc::new(EthHostExecutor::eth(chain_spec.clone(), None));
    let consumer_tip = Arc::new(AtomicU64::new(start_cursor.saturating_sub(1)));

    let driver = Arc::new(Driver::new(DriverConfig {
        factory,
        rpc: l2_provider.clone(),
        host_executor,
        hub: Arc::clone(&hub),
        chain_spec,
        witness_from_block: start_cursor,
        orchestrator_checkpoint: 0,
        l2_safe_blocks,
        consumer_tip: Arc::clone(&consumer_tip),
        max_lookahead_blocks,
    })?);

    let (task_tx, task_rx) = async_channel::bounded::<types::ExecuteTask>(sp1_workers * 2);

    // Strict-prefix watermark across SP1 workers and window-worker
    // empty-block skips. Initialized at `start_cursor` — the next block
    // we expect to see complete.
    let tracker = Arc::new(Mutex::new(CompletionTracker::new(start_cursor)));

    let shutdown = CancellationToken::new();
    let mut tasks: tokio::task::JoinSet<(&'static str, eyre::Result<()>)> =
        tokio::task::JoinSet::new();

    // Signal handler — graceful shutdown on SIGTERM/SIGINT.
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

    // Metrics HTTP server.
    {
        let shutdown = shutdown.clone();
        let addr = metrics_listen_addr.clone();
        let handle = Arc::clone(&metrics_handle);
        tasks.spawn(async move {
            let r = metrics::run_server(addr, handle, shutdown).await;
            ("metrics_server", r)
        });
    }

    // Driver one-shot catchup; non-blocking — same pattern as orchestrator.
    let catchup_handle = {
        let driver = Arc::clone(&driver);
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            if let Err(e) = driver.advance_to_witness_from_block(&shutdown).await {
                error!(err = %e, "driver_catchup: fatal — cancelling shutdown");
                shutdown.cancel();
            }
        })
    };

    // Driver background loop.
    {
        let driver = Arc::clone(&driver);
        let shutdown = shutdown.clone();
        tasks.spawn(async move {
            let r = driver.run_background_loop(shutdown).await;
            ("driver_loop", r)
        });
    }

    // Window worker (single producer).
    {
        let driver = Arc::clone(&driver);
        let task_tx = task_tx.clone();
        let db = Arc::clone(&db);
        let consumer_tip = Arc::clone(&consumer_tip);
        let tracker = Arc::clone(&tracker);
        let shutdown = shutdown.clone();
        tasks.spawn(async move {
            let r = window_worker::run(
                driver,
                task_tx,
                db,
                consumer_tip,
                tracker,
                start_cursor,
                window_size,
                skip_empty_blocks,
                shutdown,
            )
            .await;
            ("window_worker", r)
        });
    }

    // SP1 worker pool.
    for worker_id in 0..sp1_workers {
        let task_rx = task_rx.clone();
        let elf_bytes = Arc::clone(&elf_bytes);
        let consumer_tip = Arc::clone(&consumer_tip);
        let tracker = Arc::clone(&tracker);
        let db = Arc::clone(&db);
        let shutdown = shutdown.clone();
        tasks.spawn(async move {
            sp1_worker::run(worker_id, task_rx, elf_bytes, consumer_tip, tracker, db, shutdown)
                .await;
            ("sp1_worker", Ok(()))
        });
    }
    drop(task_tx);

    // Race the JoinSet — first exit cancels the rest.
    let mut exit_code = 0;
    while let Some(join) = tasks.join_next().await {
        match join {
            Ok((name, Ok(()))) => info!(worker = name, "background task exited cleanly"),
            Ok((name, Err(e))) => {
                error!(worker = name, err = %e, "background task exited with error");
                exit_code = 1;
                shutdown.cancel();
            }
            Err(e) => {
                error!(err = %e, "background task join failed");
                exit_code = 1;
                shutdown.cancel();
            }
        }
    }

    let _ = catchup_handle.await;
    if let Err(e) = hub.flush_pending().await {
        error!(err = %e, "cold witness flush_pending failed at shutdown");
    }

    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}
