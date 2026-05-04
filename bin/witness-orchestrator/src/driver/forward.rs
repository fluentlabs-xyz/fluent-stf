//! Writable `ProviderFactory` open path and the embedded forward-sync driver.
//!
//! The driver runs as an autonomous background actor: consumers build an
//! `Arc<Driver>`, call `advance_to_witness_from_block` once at startup, then
//! spawn `run_background_loop` which pulls blocks from L2 RPC, commits them
//! to MDBX, produces witnesses, and pushes them into the `WitnessHub` at a
//! rate bounded by the orchestrator-supplied `Arc<AtomicU64>` lookahead
//! watermark. Witness consumers (feeder, witness-server) read from the hub
//! directly.

use std::{
    ops::RangeInclusive,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use alloy_eips::{BlockNumberOrTag, Encodable2718};
use alloy_network::Ethereum;
use alloy_primitives::B256;
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_client::BatchRequest;
use eyre::eyre;
use fluent_stf_primitives::{
    BRIDGE_ADDRESS, BRIDGE_DEPOSIT_TOPIC, BRIDGE_ROLLBACK_TOPIC, BRIDGE_WITHDRAWAL_TOPIC,
    LEGACY_BRIDGE_WITHDRAWAL_TOPIC,
};
use futures::stream::StreamExt;
use l1_rollup_client::L2BlockHeader;
use reth_chain_state::{ComputedTrieData, ExecutedBlock};
use reth_chainspec::ChainSpec;
use reth_db::{init_db, mdbx::DatabaseArguments, ClientVersion, DatabaseEnv};
use reth_db_common::init::init_genesis;
use reth_evm::execute::{BasicBlockExecutor, BlockExecutionOutput, Executor};
use reth_node_types::NodeTypesWithDBAdapter;
use reth_primitives_traits::Block as _;
use reth_provider::{
    providers::{
        BlockchainProvider, NodeTypesForProvider, ProviderFactory, RocksDBProvider,
        StaticFileProvider,
    },
    static_file::StaticFileSegment,
    BlockBodyIndicesProvider, BlockNumReader, BlockReader, DatabaseProviderFactory, HeaderProvider,
    LatestStateProviderRef, ReceiptProvider, SaveBlocksMode, StateRootProvider,
    StaticFileProviderFactory, StaticFileWriter,
};
use reth_prune::Pruner;
use reth_prune_types::MINIMUM_UNWIND_SAFE_DISTANCE;
use reth_revm::database::StateProviderDatabase;
use reth_storage_api::BlockExecutionWriter;
use reth_trie::{HashedPostState, KeccakKeyHasher};
use rsp_client_executor::{evm::FluentEvmConfig, IntoPrimitives};
use rsp_host_executor::EthHostExecutor;
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::{
    events_hash_reth::{
        calculate_deposit_hash_from_reth_receipts, calculate_withdrawal_root_from_reth_receipts,
        count_deposits_from_reth_receipts,
    },
    hub::WitnessHub,
};

use super::node_types::FluentMdbxNode;

/// Concrete node type used by the driver. `ProviderFactory` requires
/// `NodeTypesWithDB`, which the adapter supplies by bolting `DatabaseEnv`
/// onto our bare `NodeTypes` binding.
type DriverNode = NodeTypesWithDBAdapter<FluentMdbxNode, DatabaseEnv>;

/// Concrete pruner type: built via `PrunerBuilder::build_with_provider_factory`
/// against the driver's `ProviderFactory`.
pub(crate) type DriverPruner = Pruner<
    <ProviderFactory<DriverNode> as DatabaseProviderFactory>::ProviderRW,
    ProviderFactory<DriverNode>,
>;

/// Idle poll interval — how long to sleep when remote tip has not advanced.
const IDLE_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Backoff after a transient RPC error before retrying tip lookup.
const RPC_ERROR_BACKOFF: Duration = Duration::from_secs(5);

/// Number of blocks per JSON-RPC batch during the commit-only catch-up path.
/// One HTTP POST carries `CATCHUP_BATCH_SIZE` `eth_getBlockByNumber` calls,
/// cutting per-block HTTP overhead and reducing load on the remote node.
const CATCHUP_BATCH_SIZE: u64 = 128;

/// Number of batch fetches kept in flight. With `CATCHUP_BATCH_SIZE = 64`
/// and `CATCHUP_BATCH_PIPELINE = 2` the driver prefetches up to 128 blocks
/// ahead while `commit_phase` drains them sequentially.
const CATCHUP_BATCH_PIPELINE: usize = 2;

/// Open a writable `ProviderFactory<N>` against a fresh or existing
/// reth datadir. Layout: `<datadir>/{db,static_files,rocksdb}`.
pub(crate) fn open_writable_factory<N>(
    datadir: &Path,
    chain_spec: Arc<ChainSpec>,
    mdbx_max_size: u64,
    runtime: reth_tasks::Runtime,
) -> eyre::Result<ProviderFactory<NodeTypesWithDBAdapter<N, DatabaseEnv>>>
where
    N: NodeTypesForProvider<
        ChainSpec = ChainSpec,
        Primitives = reth_ethereum_primitives::EthPrimitives,
    >,
{
    std::fs::create_dir_all(datadir)?;
    let db_path = datadir.join("db");
    let sf_path = datadir.join("static_files");
    let rocks_path = datadir.join("rocksdb");

    std::fs::create_dir_all(&db_path)?;
    std::fs::create_dir_all(&sf_path)?;
    std::fs::create_dir_all(&rocks_path)?;

    let db_args = DatabaseArguments::new(ClientVersion::default())
        .with_geometry_max_size(Some(mdbx_max_size as usize));

    let db = init_db(&db_path, db_args).map_err(|e| eyre!("init_db: {e}"))?;

    let sf = StaticFileProvider::<N::Primitives>::read_write(&sf_path)
        .map_err(|e| eyre!("static_file_provider rw: {e}"))?;

    let rocks = RocksDBProvider::builder(&rocks_path)
        .with_default_tables()
        .build()
        .map_err(|e| eyre!("rocksdb_provider build: {e}"))?;

    let factory = ProviderFactory::<NodeTypesWithDBAdapter<N, DatabaseEnv>>::new(
        db, chain_spec, sf, rocks, runtime,
    )
    .map_err(|e| eyre!("provider_factory: {e}"))?;

    heal_static_files_if_needed(&factory)?;

    Ok(factory)
}

/// Self-heal static_files that got ahead of the MDBX tip.
///
/// reth's `save_blocks` is not atomic between static-file commits and
/// the MDBX commit: if the process dies (SIGKILL, OOM, power loss, panic)
/// between them, the static_files `.conf` tail pointer moves forward
/// while MDBX stays at the previous tip. On next open, the static-file
/// provider insists on the next append being `static_tip + 1`, but
/// `save_blocks` would hand it `mdbx_tip + 1` → "expected block N but
/// got N-1".
///
/// Fix: on startup, if any of Headers / Transactions / Receipts segments
/// point to a block above the MDBX tip, queue a prune back to MDBX tip
/// and commit. Next `save_blocks` then resumes cleanly.
fn heal_static_files_if_needed<N>(
    factory: &ProviderFactory<NodeTypesWithDBAdapter<N, DatabaseEnv>>,
) -> eyre::Result<()>
where
    N: NodeTypesForProvider<
        ChainSpec = ChainSpec,
        Primitives = reth_ethereum_primitives::EthPrimitives,
    >,
{
    let mdbx_tip = factory.best_block_number().map_err(|e| eyre!("best_block_number: {e}"))?;
    if mdbx_tip == 0 {
        // Pre-genesis: leave initialization to `init_genesis`.
        return Ok(());
    }

    let sf = factory.static_file_provider();

    let headers_tip = sf.get_highest_static_file_block(StaticFileSegment::Headers).unwrap_or(0);
    let txs_tip = sf.get_highest_static_file_block(StaticFileSegment::Transactions).unwrap_or(0);
    let receipts_tip = sf.get_highest_static_file_block(StaticFileSegment::Receipts).unwrap_or(0);

    // Inverse case (static_files behind MDBX) is impossible under reth's current
    // `save_blocks` ordering — static_files are committed BEFORE MDBX. Surface
    // loudly in dev/test if the invariant breaks.
    debug_assert!(
        headers_tip >= mdbx_tip,
        "static_files Headers tip {headers_tip} < mdbx_tip {mdbx_tip} — invariant broken"
    );
    debug_assert!(
        txs_tip >= mdbx_tip,
        "static_files Transactions tip {txs_tip} < mdbx_tip {mdbx_tip} — invariant broken"
    );
    debug_assert!(
        receipts_tip >= mdbx_tip,
        "static_files Receipts tip {receipts_tip} < mdbx_tip {mdbx_tip} — invariant broken"
    );

    if headers_tip <= mdbx_tip && txs_tip <= mdbx_tip && receipts_tip <= mdbx_tip {
        return Ok(());
    }

    warn!(
        mdbx_tip,
        headers_tip,
        txs_tip,
        receipts_tip,
        "static_files ahead of MDBX tip — healing (previous run likely killed \
         between save_blocks and MDBX commit)"
    );

    if headers_tip > mdbx_tip {
        let to_delete = headers_tip - mdbx_tip;
        let mut w = sf
            .get_writer(mdbx_tip, StaticFileSegment::Headers)
            .map_err(|e| eyre!("heal: headers writer: {e}"))?;
        w.prune_headers(to_delete).map_err(|e| eyre!("heal: prune_headers: {e}"))?;
        w.commit().map_err(|e| eyre!("heal: headers commit: {e}"))?;
    }

    if txs_tip > mdbx_tip || receipts_tip > mdbx_tip {
        let last_tx_at_tip = {
            let db_provider = factory
                .database_provider_ro()
                .map_err(|e| eyre!("heal: database_provider_ro: {e}"))?;
            let body = db_provider
                .block_body_indices(mdbx_tip)
                .map_err(|e| eyre!("heal: block_body_indices({mdbx_tip}): {e}"))?
                .ok_or_else(|| eyre!("heal: no block_body_indices for MDBX tip {mdbx_tip}"))?;
            body.last_tx_num()
        };

        if txs_tip > mdbx_tip {
            let highest_static_tx =
                sf.get_highest_static_file_tx(StaticFileSegment::Transactions).unwrap_or(0);
            let to_delete = highest_static_tx.saturating_sub(last_tx_at_tip);
            if to_delete > 0 {
                let mut w = sf
                    .get_writer(mdbx_tip, StaticFileSegment::Transactions)
                    .map_err(|e| eyre!("heal: txs writer: {e}"))?;
                w.prune_transactions(to_delete, mdbx_tip)
                    .map_err(|e| eyre!("heal: prune_transactions: {e}"))?;
                w.commit().map_err(|e| eyre!("heal: txs commit: {e}"))?;
            }
        }

        if receipts_tip > mdbx_tip {
            let highest_static_rx =
                sf.get_highest_static_file_tx(StaticFileSegment::Receipts).unwrap_or(0);
            let to_delete = highest_static_rx.saturating_sub(last_tx_at_tip);
            if to_delete > 0 {
                let mut w = sf
                    .get_writer(mdbx_tip, StaticFileSegment::Receipts)
                    .map_err(|e| eyre!("heal: receipts writer: {e}"))?;
                w.prune_receipts(to_delete, mdbx_tip)
                    .map_err(|e| eyre!("heal: prune_receipts: {e}"))?;
                w.commit().map_err(|e| eyre!("heal: receipts commit: {e}"))?;
            }
        }
    }

    // Refresh the in-memory segment index so subsequent readers see the
    // truncated state.
    sf.initialize_index().map_err(|e| eyre!("heal: initialize_index: {e}"))?;

    info!(mdbx_tip, "heal: static_files truncated to MDBX tip");
    Ok(())
}

/// Initialise genesis on an empty datadir; no-op if already populated.
fn ensure_genesis_initialized(factory: &ProviderFactory<DriverNode>) -> eyre::Result<()> {
    let tip = factory.best_block_number().map_err(|e| eyre!("best_block_number: {e}"))?;
    if tip > 0 {
        info!(tip, "datadir already initialized, resuming");
        return Ok(());
    }
    let genesis_hash = init_genesis(factory).map_err(|e| eyre!("init_genesis: {e}"))?;
    info!(?genesis_hash, "genesis initialized");
    Ok(())
}

pub(crate) struct DriverConfig {
    pub factory: ProviderFactory<DriverNode>,
    pub rpc: RootProvider<Ethereum>,
    pub host_executor: Arc<EthHostExecutor>,
    pub hub: Arc<WitnessHub>,
    pub chain_spec: Arc<ChainSpec>,
    /// Optional reth pruner. When `Some`, invoked after every successful
    /// block commit — the pruner itself throttles via its `block_interval`.
    pub pruner: Option<DriverPruner>,
    /// First block that requires a full witness. Blocks below this threshold
    /// are commit-only (MDBX sync without witness/cold-store/ProveRequest).
    /// Set to 0 to witness every block (default when L1_START_BATCH_ID is unset).
    pub witness_from_block: u64,
    /// Pipeline-confirmed watermark from the orchestrator's SQLite store.
    /// The driver's resume cursor is `max(orchestrator_checkpoint + 1, witness_from_block)`.
    pub orchestrator_checkpoint: u64,
    /// Safety lag behind the remote L2 tip (reorg protection). Applied in
    /// `advance_to_witness_from_block` and the background loop as
    /// `remote_tip.saturating_sub(l2_safe_blocks)`.
    pub l2_safe_blocks: u64,
}

/// A block fetched from RPC together with the time it took to pull.
struct FetchedBlock {
    block_number: u64,
    alloy_block: alloy_rpc_types::Block,
    fetch_ms: u64,
}

/// Commit-phase output — everything the witness phase needs plus the
/// pre-witness per-phase timings.
struct WitnessJob {
    block_number: u64,
    prim_block: reth_ethereum_primitives::Block,
    parent_state_root: alloy_primitives::B256,
    fetch_ms: u64,
    execute_ms: u64,
    trie_ms: u64,
    save_ms: u64,
    t_total_start: Instant,
}

/// Pull-shaped forward-sync driver. Construct once, then drive through the
/// two public async methods. The driver serializes MDBX-writing work
/// internally and survives any number of concurrent `&self` callers.
pub(crate) struct Driver {
    factory: ProviderFactory<DriverNode>,
    rpc: RootProvider<Ethereum>,
    host_executor: Arc<EthHostExecutor>,
    hub: Arc<WitnessHub>,
    chain_spec: Arc<ChainSpec>,
    witness_from_block: u64,
    /// MDBX tip captured at startup. Re-witness range is
    /// `[orchestrator_checkpoint+1 ..= start_tip]` (stable for process lifetime).
    start_tip: u64,
    /// Flipped to `true` by `advance_to_witness_from_block` on completion.
    /// `run_background_loop` waits for this before producing witnesses.
    ready: AtomicBool,
    /// Mutable cursor + pruner. Held only during actual work; callers wait
    /// here while another call is in flight (MDBX writable txn is single-writer).
    state: AsyncMutex<DriverState>,
    l2_safe_blocks: u64,
}

struct DriverState {
    /// Next block number to process.
    next: u64,
    pruner: Option<DriverPruner>,
}

impl Driver {
    /// Construct the driver. Runs genesis init, static-file heal, invariant
    /// checks (cold_last vs mdbx_tip, PRUNE_FULL vs witness_from_block).
    /// Fails loudly on any invariant violation.
    pub(crate) fn new(cfg: DriverConfig) -> eyre::Result<Self> {
        ensure_genesis_initialized(&cfg.factory)?;

        // Cold writes are buffered across up to `DEFAULT_COLD_BATCH_SIZE` blocks
        // for tip-following; a crash between batch flushes leaves `cold_last`
        // trailing `mdbx_tip`. This is recoverable: the driver's re-witness
        // path (`try_take_new_block`, `block_number <= start_tip`) falls through
        // to `rewitness_phase` on cold miss, which rebuilds the payload from
        // MDBX and pushes it back into cold. So trailing `cold_last` is logged
        // but not fatal. Only the inverse (`cold_last > mdbx_tip`) would
        // indicate a real violation — redb committed a witness whose MDBX
        // parent state is missing — but we do not currently write cold before
        // MDBX, so that case cannot arise here.
        let witness_from_block = cfg.witness_from_block;
        let mdbx_tip =
            cfg.factory.best_block_number().map_err(|e| eyre!("best_block_number: {e}"))?;
        let cold_last =
            cfg.hub.last_committed_block().map_err(|e| eyre!("hub.last_committed_block: {e}"))?;
        if let Some(cl) = cold_last {
            if mdbx_tip >= witness_from_block && cl < mdbx_tip {
                warn!(
                    cold_last = cl,
                    mdbx_tip,
                    gap = mdbx_tip - cl,
                    "cold store trails MDBX tip — previous run likely crashed between batch \
                     flushes; re-witness path will refill the gap on resume"
                );
            }
        }
        let start_tip = mdbx_tip;

        // Startup safety: if PRUNE_FULL is on and the tip is far past
        // witness_from_block, the history needed to re-witness blocks
        // [witness_from_block..start_tip] may already have been pruned.
        if cfg.pruner.is_some() &&
            witness_from_block <= start_tip &&
            start_tip - witness_from_block > MINIMUM_UNWIND_SAFE_DISTANCE
        {
            return Err(eyre!(
                "PRUNE_FULL=true but mdbx_tip ({start_tip}) is {} blocks past \
                 witness_from_block ({witness_from_block}) — account_history/storage_history \
                 needed to re-witness blocks [{witness_from_block}..{start_tip}] may already \
                 have been pruned (MINIMUM_UNWIND_SAFE_DISTANCE = {}). Either disable \
                 PRUNE_FULL, or restore from a snapshot whose mdbx_tip is within {} blocks \
                 of witness_from_block.",
                start_tip - witness_from_block,
                MINIMUM_UNWIND_SAFE_DISTANCE,
                MINIMUM_UNWIND_SAFE_DISTANCE,
            ));
        }

        // Resume cursor: max of pipeline-confirmed checkpoint and first
        // witness-required block, clamped to `start_tip + 1` so the driver never
        // skips past its own MDBX tip. When MDBX is behind `witness_from_block`
        // (e.g. first run with a high L1_START_BATCH_ID against a fresh datadir),
        // the clamp routes blocks [start_tip+1 .. witness_from_block-1] through
        // the commit-only fast path instead of the full-witness path, which
        // would otherwise fail with StateAtBlockNotAvailable on the parent lookup.
        let next = (cfg.orchestrator_checkpoint + 1).max(witness_from_block).min(start_tip + 1);
        info!(
            mdbx_tip = start_tip,
            cold_last = ?cold_last,
            orchestrator_checkpoint = cfg.orchestrator_checkpoint,
            witness_from_block,
            next,
            "Driver initialized"
        );

        Ok(Self {
            factory: cfg.factory,
            rpc: cfg.rpc,
            host_executor: cfg.host_executor,
            hub: cfg.hub,
            chain_spec: cfg.chain_spec,
            witness_from_block,
            start_tip,
            ready: AtomicBool::new(false),
            state: AsyncMutex::new(DriverState { next, pruner: cfg.pruner }),
            l2_safe_blocks: cfg.l2_safe_blocks,
        })
    }

    /// One-shot startup catch-up: MDBX-commits every block in
    /// `[next .. witness_from_block)` without producing witnesses. Uses the
    /// batched-prefetch pipeline (CATCHUP_BATCH_SIZE / CATCHUP_BATCH_PIPELINE).
    /// Sets `ready = true` on successful completion. Must be called exactly
    /// once before any `try_take_new_block` call returns a witness.
    pub(crate) async fn advance_to_witness_from_block(
        &self,
        shutdown: &CancellationToken,
    ) -> eyre::Result<()> {
        let mut state = self.state.lock().await;

        // Nothing to do — already past catch-up.
        if state.next >= self.witness_from_block {
            self.ready.store(true, Ordering::Release);
            return Ok(());
        }

        loop {
            if shutdown.is_cancelled() {
                info!("Shutdown requested mid-catch-up — driver exiting");
                return Ok(());
            }

            let remote_tip = match self.rpc.get_block_number().await {
                Ok(t) => t,
                Err(e) => {
                    warn!(err = %e, "rpc get_block_number failed — backing off");
                    tokio::select! {
                        _ = shutdown.cancelled() => return Ok(()),
                        _ = tokio::time::sleep(RPC_ERROR_BACKOFF) => continue,
                    }
                }
            };

            let catchup_upper =
                remote_tip.saturating_sub(self.l2_safe_blocks).min(self.witness_from_block - 1);
            if state.next > catchup_upper {
                tokio::select! {
                    _ = shutdown.cancelled() => return Ok(()),
                    _ = tokio::time::sleep(IDLE_POLL_INTERVAL) => continue,
                }
            }

            // Chunk [state.next ..= catchup_upper] into batches of up to
            // CATCHUP_BATCH_SIZE blocks.
            let start = state.next;
            let mut ranges: Vec<(u64, u64)> = Vec::new();
            {
                let mut s = start;
                while s <= catchup_upper {
                    let e = s.saturating_add(CATCHUP_BATCH_SIZE - 1).min(catchup_upper);
                    ranges.push((s, e));
                    s = e + 1;
                }
            }

            let rpc = self.rpc.clone();
            let mut batch_stream = futures::stream::iter(ranges)
                .map(move |(s, e)| {
                    let rpc = rpc.clone();
                    async move { (s, e, fetch_batch(&rpc, s, e).await) }
                })
                .buffered(CATCHUP_BATCH_PIPELINE);

            let mut fetch_failed = false;
            loop {
                let (s, e, fetch_result) = tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => {
                        info!("Shutdown requested mid-catch-up — driver exiting");
                        return Ok(());
                    }
                    item = batch_stream.next() => match item {
                        Some(x) => x,
                        None => break,
                    }
                };

                let fetched_batch = match fetch_result {
                    Ok(v) => v,
                    Err(err) => {
                        warn!(
                            range_start = s,
                            range_end = e,
                            err = %err,
                            "fetch_batch failed — retrying range"
                        );
                        tokio::select! {
                            _ = shutdown.cancelled() => return Ok(()),
                            _ = tokio::time::sleep(RPC_ERROR_BACKOFF) => {}
                        }
                        fetch_failed = true;
                        break;
                    }
                };

                if shutdown.is_cancelled() {
                    info!("Shutdown requested mid-catch-up — driver exiting");
                    return Ok(());
                }

                // Commit the whole [s..=e] range inside ONE MDBX transaction:
                // each block is executed against `LatestStateProviderRef(&provider_rw)`
                // which reads via the RW txn's cursors and therefore sees prior
                // blocks' uncommitted writes within the same batch. One
                // `provider_rw.commit()` at the end turns CATCHUP_BATCH_SIZE fsyncs
                // into a single fsync.
                let factory_clone = self.factory.clone();
                let chain_spec_clone = Arc::clone(&self.chain_spec);
                let t_commit = Instant::now();
                tokio::task::spawn_blocking(move || {
                    commit_batch(&factory_clone, &chain_spec_clone, fetched_batch)
                })
                .await
                .map_err(|e| eyre!("commit_batch join: {e}"))??;

                info!(
                    range_start = s,
                    range_end = e,
                    witness_from_block = self.witness_from_block,
                    commit_ms = t_commit.elapsed().as_millis() as u64,
                    "Catch-up: committed batch (no witness)"
                );
                if e + 1 == self.witness_from_block {
                    info!(
                        block_number = e,
                        witness_from_block = self.witness_from_block,
                        "Catch-up complete — switching to full witness mode"
                    );
                }

                // Pruner reads committed state; must run after `commit_batch`.
                run_pruner_if_needed(&mut state.pruner, e).await;

                state.next = e + 1;
            }

            if fetch_failed {
                continue;
            }

            if state.next >= self.witness_from_block {
                info!(
                    next = state.next,
                    witness_from_block = self.witness_from_block,
                    "Catch-up complete — driver ready for witness requests"
                );
                self.ready.store(true, Ordering::Release);
                return Ok(());
            }
        }
    }

    /// Resolve the witness payload for an already-known block.
    ///
    /// Fast path: cold-store hit — returns the cached bincode payload verbatim.
    ///
    /// Slow path (cold miss): fetches the block body from the L2 RPC and
    /// rebuilds the witness against the MDBX state at `block_number - 1`. This
    /// is the same machinery `try_take_new_block` uses when re-feeding blocks
    /// evicted from the retention window, lifted into a standalone entry point
    /// so external consumers (HTTP witness server, post-key-rotation re-exec
    /// in the orchestrator) can depend on cold storage without treating a miss
    /// as fatal.
    ///
    /// Returns `Ok(None)` when the block cannot be served: either beyond the
    /// current MDBX tip (not yet committed) or block zero (no parent state).
    /// Returns `Err(_)` only on a fatal rebuild failure (RPC error, executor
    /// failure, serialization failure).
    pub(crate) async fn get_or_build_witness(
        &self,
        block_number: u64,
    ) -> eyre::Result<Option<Vec<u8>>> {
        if let Some(cached) = self.hub.get_witness(block_number).await {
            return Ok(Some(cached.payload));
        }

        if block_number == 0 {
            return Ok(None);
        }
        let mdbx_tip =
            self.factory.best_block_number().map_err(|e| eyre!("best_block_number: {e}"))?;
        if block_number > mdbx_tip {
            return Ok(None);
        }

        let fetched = fetch_block(&self.rpc, block_number).await?;
        let payload = rewitness_phase(
            fetched,
            self.factory.clone(),
            Arc::clone(&self.host_executor),
            Arc::clone(&self.hub),
        )
        .await?;
        Ok(Some(payload))
    }

    /// Per-block `(L2BlockHeader, merkle leaf)` for every block in
    /// `range`, read from MDBX. Returns `Ok(None)` when
    /// `range.end() > mdbx_tip` so the caller can retry on the next
    /// worker tick instead of falling back to RPC. Target-leaf lookup
    /// (`leaves.iter().position(...)`) is left to the caller.
    pub(crate) async fn collect_l2_block_headers(
        &self,
        range: RangeInclusive<u64>,
    ) -> eyre::Result<Option<(Vec<L2BlockHeader>, Vec<B256>)>> {
        let from = *range.start();
        let to = *range.end();
        debug_assert!(from <= to, "collect_l2_block_headers requires from ({from}) <= to ({to})");
        let mdbx_tip =
            self.factory.best_block_number().map_err(|e| eyre!("best_block_number: {e}"))?;
        if to > mdbx_tip {
            return Ok(None);
        }

        let factory = self.factory.clone();
        tokio::task::spawn_blocking(move || -> eyre::Result<_> {
            let provider =
                factory.database_provider_ro().map_err(|e| eyre!("database_provider_ro: {e}"))?;

            let sealed = provider
                .sealed_headers_range(from..=to)
                .map_err(|e| eyre!("sealed_headers_range: {e}"))?;
            let receipts_per_block = provider
                .receipts_by_block_range(from..=to)
                .map_err(|e| eyre!("receipts_by_block_range: {e}"))?;

            let expected = (to - from + 1) as usize;
            if sealed.len() != expected || receipts_per_block.len() != expected {
                return Err(eyre!(
                    "MDBX read length mismatch for range [{from}..={to}]: \
                     headers={}, receipts={}, expected={expected}",
                    sealed.len(),
                    receipts_per_block.len(),
                ));
            }

            let mut headers = Vec::with_capacity(expected);
            let mut leaves = Vec::with_capacity(expected);
            for (sh, rxs) in sealed.into_iter().zip(receipts_per_block.iter()) {
                let parent_hash = sh.header().parent_hash;
                let block_hash = sh.hash();
                let withdrawal_root = calculate_withdrawal_root_from_reth_receipts(
                    rxs,
                    BRIDGE_ADDRESS,
                    BRIDGE_WITHDRAWAL_TOPIC,
                    LEGACY_BRIDGE_WITHDRAWAL_TOPIC,
                    BRIDGE_ROLLBACK_TOPIC,
                );
                let deposit_root = calculate_deposit_hash_from_reth_receipts(
                    rxs,
                    BRIDGE_ADDRESS,
                    BRIDGE_DEPOSIT_TOPIC,
                );
                let deposit_count =
                    count_deposits_from_reth_receipts(rxs, BRIDGE_ADDRESS, BRIDGE_DEPOSIT_TOPIC);
                let leaf = batch_merkle::compute_leaf(
                    parent_hash,
                    block_hash,
                    withdrawal_root,
                    deposit_root,
                );
                headers.push(L2BlockHeader {
                    previousBlockHash: parent_hash,
                    blockHash: block_hash,
                    withdrawalRoot: withdrawal_root,
                    depositRoot: deposit_root,
                    depositCount: deposit_count,
                });
                leaves.push(leaf);
            }
            Ok((headers, leaves))
        })
        .await
        .map_err(|e| eyre!("collect_l2_block_headers join: {e}"))?
        .map(Some)
    }

    /// MDBX-backed read of header-RLP + tx-envelope-bytes per block,
    /// shaped to slot directly into `rsp_blob_builder`'s encoder pipeline.
    /// Returns `Ok(None)` when `range.end() > mdbx_tip` (caller retries
    /// next tick).
    pub(crate) async fn collect_blob_inputs(
        &self,
        range: RangeInclusive<u64>,
    ) -> eyre::Result<Option<Vec<rsp_blob_builder::FetchedBlock>>> {
        let from = *range.start();
        let to = *range.end();
        debug_assert!(from <= to, "collect_blob_inputs requires from ({from}) <= to ({to})");
        let mdbx_tip =
            self.factory.best_block_number().map_err(|e| eyre!("best_block_number: {e}"))?;
        if to > mdbx_tip {
            return Ok(None);
        }

        let factory = self.factory.clone();
        tokio::task::spawn_blocking(move || -> eyre::Result<_> {
            let provider =
                factory.database_provider_ro().map_err(|e| eyre!("database_provider_ro: {e}"))?;
            let blocks = provider.block_range(from..=to).map_err(|e| eyre!("block_range: {e}"))?;
            let expected = (to - from + 1) as usize;
            if blocks.len() != expected {
                return Err(eyre!(
                    "MDBX block_range returned {} of {expected} expected blocks for [{from}..={to}]",
                    blocks.len(),
                ));
            }
            let mut out = Vec::with_capacity(expected);
            for block in blocks {
                let header_rlp = alloy_rlp::encode(&block.header);
                let tx_envelopes: Vec<Vec<u8>> =
                    block.body.transactions.iter().map(|tx| tx.encoded_2718()).collect();
                out.push(rsp_blob_builder::FetchedBlock { header_rlp, tx_envelopes });
            }
            Ok(out)
        })
        .await
        .map_err(|e| eyre!("collect_blob_inputs join: {e}"))?
        .map(Some)
    }

    /// Run the autonomous forward-sync loop until `shutdown` fires. Waits for
    /// `advance_to_witness_from_block` to flip `ready`, then repeatedly produces
    /// the next witness (re-witness branch for `state.next <= start_tip`,
    /// tip-following branch above) and pushes the payload into `WitnessHub`.
    /// Production is bounded by the live L2 chain via
    /// `remote_tip - l2_safe_blocks` inside the tip-following branch; consumers
    /// read from the hub directly.
    ///
    /// Returns `Err(_)` only on an unrecoverable MDBX / witness-build / hub
    /// push failure — the caller should cancel the root shutdown token on
    /// that signal.
    pub(crate) async fn run_background_loop(
        self: Arc<Self>,
        shutdown: CancellationToken,
    ) -> eyre::Result<()> {
        // Wait for one-shot catch-up to flip `ready`. Short poll interval so
        // the loop is responsive to shutdown during catch-up.
        while !self.ready.load(Ordering::Acquire) {
            if shutdown.is_cancelled() {
                return Ok(());
            }
            tokio::select! {
                _ = shutdown.cancelled() => return Ok(()),
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
        }

        loop {
            if shutdown.is_cancelled() {
                info!("Driver loop: shutdown — exiting");
                return Ok(());
            }

            match self.produce_next_witness(&shutdown).await? {
                Produced::Pushed => {}
                Produced::Idle => {
                    tokio::select! {
                        _ = shutdown.cancelled() => return Ok(()),
                        _ = tokio::time::sleep(IDLE_POLL_INTERVAL) => continue,
                    }
                }
            }
        }
    }

    /// Produce the next witness: fetch/commit/witness for a fresh block or
    /// re-witness an already-MDBX-committed one, then push the payload into
    /// `WitnessHub`. Advances `state.next` on success. Returns `Produced::Idle`
    /// when the remote tip is caught up or a transient error was absorbed.
    async fn produce_next_witness(&self, shutdown: &CancellationToken) -> eyre::Result<Produced> {
        let mut state = self.state.lock().await;
        let block_number = state.next;

        // ── Re-witness path (block already MDBX-committed) ────────────────
        if block_number <= self.start_tip {
            // Cold-store hit short-circuit: payload already persisted; feeder
            // reads it from the hub. No need to rebuild or re-push.
            if self.hub.get_witness(block_number).await.is_some() {
                info!(
                    block_number,
                    "Re-witness served from cold store (skipped rebuild + re-push)"
                );
                metrics::gauge!(crate::metrics::LAST_BLOCK_WITNESS_BUILT).set(block_number as f64);
                state.next = block_number + 1;
                return Ok(Produced::Pushed);
            }

            let fetched = match fetch_block(&self.rpc, block_number).await {
                Ok(f) => f,
                Err(e) => {
                    warn!(
                        block_number,
                        err = %e,
                        "fetch_block failed during re-witness — will retry"
                    );
                    tokio::select! {
                        _ = shutdown.cancelled() => return Ok(Produced::Idle),
                        _ = tokio::time::sleep(RPC_ERROR_BACKOFF) => {}
                    }
                    return Ok(Produced::Idle);
                }
            };

            let payload = rewitness_phase(
                fetched,
                self.factory.clone(),
                Arc::clone(&self.host_executor),
                Arc::clone(&self.hub),
            )
            .await?;

            // Pruner is skipped here — nothing was committed, so there is
            // nothing new to prune.
            self.hub.push(block_number, &payload).await?;
            metrics::gauge!(crate::metrics::LAST_BLOCK_WITNESS_BUILT).set(block_number as f64);
            state.next = block_number + 1;
            return Ok(Produced::Pushed);
        }

        // ── Fresh tip-following path (block_number > start_tip) ───────────
        let remote_tip = match self.rpc.get_block_number().await {
            Ok(t) => t,
            Err(e) => {
                warn!(err = %e, "rpc get_block_number failed — backing off");
                tokio::select! {
                    _ = shutdown.cancelled() => return Ok(Produced::Idle),
                    _ = tokio::time::sleep(RPC_ERROR_BACKOFF) => {}
                }
                return Ok(Produced::Idle);
            }
        };
        if block_number > remote_tip.saturating_sub(self.l2_safe_blocks) {
            return Ok(Produced::Idle);
        }

        let fetched = match fetch_block(&self.rpc, block_number).await {
            Ok(f) => f,
            Err(e) => {
                warn!(block_number, err = %e, "fetch_block failed — will retry");
                tokio::select! {
                    _ = shutdown.cancelled() => return Ok(Produced::Idle),
                    _ = tokio::time::sleep(RPC_ERROR_BACKOFF) => {}
                }
                return Ok(Produced::Idle);
            }
        };

        // Wrap commit_phase in spawn_blocking — heavy sync MDBX + static_files
        // work that must not stall the async runtime.
        let factory_clone = self.factory.clone();
        let chain_spec_clone = Arc::clone(&self.chain_spec);
        let job = tokio::task::spawn_blocking(move || {
            commit_phase(&factory_clone, &chain_spec_clone, fetched)
        })
        .await
        .map_err(|e| eyre!("commit_phase join: {e}"))??;

        let payload =
            witness_phase(job, self.factory.clone(), Arc::clone(&self.host_executor)).await?;

        // Buffered cold write: batches redb fsyncs across many blocks. A crash
        // before the next flush loses the buffered block numbers from cold —
        // the re-witness path rebuilds them from MDBX on restart (cold miss →
        // rewitness_phase).
        self.hub.push_batched(block_number, &payload).await?;

        run_pruner_if_needed(&mut state.pruner, block_number).await;

        state.next = block_number + 1;
        Ok(Produced::Pushed)
    }
}

enum Produced {
    /// Produced a witness and pushed it to the hub; caller should continue.
    Pushed,
    /// No work this iteration (remote tip caught up, transient RPC error
    /// absorbed, etc.). Caller should sleep before retrying.
    Idle,
}

/// Run the pruner on `block_number` if it is due. Ownership hops via
/// `spawn_blocking` because `Pruner::run` does a lot of sync disk work.
async fn run_pruner_if_needed(slot: &mut Option<DriverPruner>, block_number: u64) {
    if let Some(p) = slot.take() {
        if p.is_pruning_needed(block_number) {
            let res = tokio::task::spawn_blocking(move || {
                let mut p = p;
                let out = p.run(block_number);
                (p, out)
            })
            .await;
            match res {
                Ok((returned, Ok(out))) => {
                    info!(block_number, ?out, "Pruner run");
                    *slot = Some(returned);
                }
                Ok((returned, Err(e))) => {
                    warn!(block_number, err = %e, "Pruner run failed");
                    *slot = Some(returned);
                }
                Err(e) => {
                    error!(
                        block_number,
                        err = %e,
                        "Pruner join failed — pruning disabled for this run, restart to restore"
                    );
                }
            }
        } else {
            *slot = Some(p);
        }
    }
}

async fn fetch_block(
    rpc: &RootProvider<Ethereum>,
    block_number: u64,
) -> eyre::Result<FetchedBlock> {
    let t_fetch = Instant::now();
    let alloy_block = rpc
        .get_block_by_number(block_number.into())
        .full()
        .await
        .map_err(|e| eyre!("rpc get_block({block_number}): {e}"))?
        .ok_or_else(|| eyre!("rpc returned no block for {block_number}"))?;
    Ok(FetchedBlock { block_number, alloy_block, fetch_ms: t_fetch.elapsed().as_millis() as u64 })
}

/// Fetch `[start ..= end_inclusive]` as a single JSON-RPC batch request —
/// one HTTP POST carrying N `eth_getBlockByNumber` calls, whose responses
/// are multiplexed back through per-call waiters.
///
/// All-or-nothing: if the batch send fails or any waiter returns an error
/// or `null`, the whole call errors out. Callers retry the entire range
/// after a backoff, matching the previous `fetch_block` semantics.
async fn fetch_batch(
    rpc: &RootProvider<Ethereum>,
    start: u64,
    end_inclusive: u64,
) -> eyre::Result<Vec<FetchedBlock>> {
    debug_assert!(start <= end_inclusive);
    let t_fetch = Instant::now();
    let mut batch = BatchRequest::new(rpc.client());

    let mut waiters = Vec::with_capacity((end_inclusive - start + 1) as usize);
    for bn in start..=end_inclusive {
        let waiter = batch
            .add_call::<_, Option<alloy_rpc_types::Block>>(
                "eth_getBlockByNumber",
                &(BlockNumberOrTag::Number(bn), true),
            )
            .map_err(|e| eyre!("rpc batch add_call block {bn}: {e}"))?;
        waiters.push((bn, waiter));
    }

    batch.send().await.map_err(|e| eyre!("rpc batch send [{start}..={end_inclusive}]: {e}"))?;

    let total_ms = t_fetch.elapsed().as_millis() as u64;
    let per_block_ms = total_ms / (end_inclusive - start + 1);

    let mut results = Vec::with_capacity(waiters.len());
    for (bn, waiter) in waiters {
        let block = waiter
            .await
            .map_err(|e| eyre!("rpc batch get_block({bn}): {e}"))?
            .ok_or_else(|| eyre!("rpc returned no block for {bn}"))?;
        results.push(FetchedBlock { block_number: bn, alloy_block: block, fetch_ms: per_block_ms });
    }

    Ok(results)
}

/// Commit phase: alloy → primitive → execute → trie → save_blocks(Full) → commit.
fn commit_phase(
    factory: &ProviderFactory<DriverNode>,
    chain_spec: &Arc<ChainSpec>,
    fetched: FetchedBlock,
) -> eyre::Result<WitnessJob> {
    let FetchedBlock { block_number, alloy_block, fetch_ms } = fetched;
    let t_total_start = Instant::now();

    let prim_block =
        <reth_ethereum_primitives::EthPrimitives as IntoPrimitives<Ethereum>>::into_primitive_block(
            alloy_block,
        );
    let recovered = prim_block
        .clone()
        .try_into_recovered()
        .map_err(|_| eyre!("recover_senders failed for block {block_number}"))?;

    let t_exec = Instant::now();
    let state_provider = factory.history_by_block_number(block_number - 1)?;
    let db = StateProviderDatabase::new(&state_provider);
    let evm_config = FluentEvmConfig::new_with_default_factory(chain_spec.clone());
    let executor = BasicBlockExecutor::new(evm_config, db);
    let exec_output: BlockExecutionOutput<_> =
        executor.execute(&recovered).map_err(|e| eyre!("execute: {e}"))?;
    let execute_ms = t_exec.elapsed().as_millis() as u64;

    let t_trie = Instant::now();
    let hashed_state =
        HashedPostState::from_bundle_state::<KeccakKeyHasher>(exec_output.state.state());
    let (state_root, trie_updates) = state_provider
        .state_root_with_updates(hashed_state.clone())
        .map_err(|e| eyre!("state_root_with_updates: {e}"))?;

    if state_root != recovered.header().state_root {
        eyre::bail!(
            "state_root mismatch at block {block_number}: computed {state_root:?}, header {:?}",
            recovered.header().state_root,
        );
    }
    let trie_ms = t_trie.elapsed().as_millis() as u64;

    drop(state_provider);
    let hashed_sorted = hashed_state.into_sorted();
    let trie_updates_sorted = trie_updates.into_sorted();
    let trie_data = ComputedTrieData {
        hashed_state: Arc::new(hashed_sorted),
        trie_updates: Arc::new(trie_updates_sorted),
        anchored_trie_input: None,
    };
    let executed = ExecutedBlock::new(Arc::new(recovered), Arc::new(exec_output), trie_data);

    let t_save = Instant::now();
    let provider_rw = factory.provider_rw()?;
    provider_rw
        .save_blocks(vec![executed], SaveBlocksMode::Full)
        .map_err(|e| eyre!("save_blocks: {e}"))?;
    provider_rw.commit().map_err(|e| eyre!("commit: {e}"))?;
    let save_ms = t_save.elapsed().as_millis() as u64;

    let parent_state_root = factory
        .header_by_number(block_number - 1)?
        .ok_or_else(|| eyre!("missing header N-1 after commit"))?
        .state_root;

    Ok(WitnessJob {
        block_number,
        prim_block,
        parent_state_root,
        fetch_ms,
        execute_ms,
        trie_ms,
        save_ms,
        t_total_start,
    })
}

/// Catch-up commit phase: MDBX-commit a consecutive range of blocks in ONE
/// transaction, verifying each block's state root against its header.
///
/// The key trick is `LatestStateProviderRef::new(&*provider_rw)`: it reads
/// through the RW txn's own cursors, so writes from prior `save_blocks` calls
/// in this batch are visible to subsequent blocks' execution and state-root
/// recomputation even though MDBX has not been committed. Static-file writes
/// are done eagerly inside `save_blocks`; a mid-batch failure drops the
/// provider_rw without commit and relies on `heal_static_files_if_needed` at
/// the next startup to re-sync static files to the MDBX tip.
///
/// Produces no `WitnessJob` — the catch-up path does not produce witnesses.
fn commit_batch(
    factory: &ProviderFactory<DriverNode>,
    chain_spec: &Arc<ChainSpec>,
    fetched_batch: Vec<FetchedBlock>,
) -> eyre::Result<()> {
    if fetched_batch.is_empty() {
        return Ok(());
    }

    let provider_rw = factory.provider_rw().map_err(|e| eyre!("provider_rw: {e}"))?;

    for fetched in fetched_batch {
        let FetchedBlock { block_number, alloy_block, .. } = fetched;

        let prim_block =
            <reth_ethereum_primitives::EthPrimitives as IntoPrimitives<Ethereum>>::into_primitive_block(
                alloy_block,
            );
        let recovered = prim_block
            .try_into_recovered()
            .map_err(|_| eyre!("recover_senders failed for block {block_number}"))?;

        let db = StateProviderDatabase::new(LatestStateProviderRef::new(&*provider_rw));
        let evm_config = FluentEvmConfig::new_with_default_factory(chain_spec.clone());
        let executor = BasicBlockExecutor::new(evm_config, db);
        let exec_output: BlockExecutionOutput<_> =
            executor.execute(&recovered).map_err(|e| eyre!("execute at {block_number}: {e}"))?;

        let hashed_state =
            HashedPostState::from_bundle_state::<KeccakKeyHasher>(exec_output.state.state());
        let state_provider = LatestStateProviderRef::new(&*provider_rw);
        let (state_root, trie_updates) = state_provider
            .state_root_with_updates(hashed_state.clone())
            .map_err(|e| eyre!("state_root_with_updates at {block_number}: {e}"))?;

        if state_root != recovered.header().state_root {
            eyre::bail!(
                "state_root mismatch at block {block_number}: computed {state_root:?}, header {:?}",
                recovered.header().state_root,
            );
        }

        let trie_data = ComputedTrieData {
            hashed_state: Arc::new(hashed_state.into_sorted()),
            trie_updates: Arc::new(trie_updates.into_sorted()),
            anchored_trie_input: None,
        };
        let executed = ExecutedBlock::new(Arc::new(recovered), Arc::new(exec_output), trie_data);

        provider_rw
            .save_blocks(vec![executed], SaveBlocksMode::Full)
            .map_err(|e| eyre!("save_blocks at {block_number}: {e}"))?;
    }

    provider_rw.commit().map_err(|e| eyre!("commit: {e}"))?;
    Ok(())
}

/// Witness phase: execute_exex_with_block + bincode (on blocking pool).
/// Returns the serialized payload, leaving storage/channel side-effects to
/// the caller.
async fn witness_phase(
    job: WitnessJob,
    factory: ProviderFactory<DriverNode>,
    host_executor: Arc<EthHostExecutor>,
) -> eyre::Result<Vec<u8>> {
    let WitnessJob {
        block_number,
        prim_block,
        parent_state_root,
        fetch_ms,
        execute_ms,
        trie_ms,
        save_ms,
        t_total_start,
    } = job;

    let t_witness = Instant::now();
    // execute_exex_with_block walks tries and runs EVM — heavy sync work;
    // push it onto the blocking pool so the async runtime stays responsive.
    let input = tokio::task::spawn_blocking(move || -> eyre::Result<_> {
        let read_view =
            BlockchainProvider::new(factory).map_err(|e| eyre!("BlockchainProvider::new: {e}"))?;
        host_executor
            .execute_exex_with_block(prim_block, parent_state_root, read_view, None)
            .map_err(|e| eyre!("execute_exex_with_block: {e}"))
    })
    .await
    .map_err(|e| eyre!("witness_phase join: {e}"))??;
    let witness_ms = t_witness.elapsed().as_millis() as u64;

    let t_ser = Instant::now();
    let payload = match tokio::task::spawn_blocking(move || bincode::serialize(&input)).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(e)) => {
            error!(block_number, err = %e, "bincode serialize failed");
            return Err(eyre!("bincode: {e}"));
        }
        Err(e) => {
            error!(block_number, err = %e, "serialize task panicked");
            return Err(eyre!("serialize task: {e}"));
        }
    };
    let serialize_ms = t_ser.elapsed().as_millis() as u64;
    let payload_bytes = payload.len() as u64;

    let total_ms = t_total_start.elapsed().as_millis() as u64;
    info!(
        block_number,
        total_ms,
        fetch_ms,
        execute_ms,
        trie_ms,
        save_ms,
        witness_ms,
        serialize_ms,
        payload_bytes,
        "Block witness built"
    );
    metrics::gauge!(crate::metrics::LAST_BLOCK_WITNESS_BUILT).set(block_number as f64);

    Ok(payload)
}

/// Re-witness phase: regenerate the witness for a block already in MDBX.
///
/// Fast path: if the cold witness store still has this block, return its
/// payload verbatim — no RPC parse, no executor run, no trie walk. This
/// matters after a startup checkpoint rollback, when the driver re-feeds a
/// range of blocks whose payloads are already persisted. Falls through to
/// the slow path when the block has been evicted from the retention window.
///
/// Slow path: reads parent state root from MDBX, runs `execute_exex_with_block`
/// against the existing state, and serializes. Does NOT commit — the block is
/// already present.
async fn rewitness_phase(
    fetched: FetchedBlock,
    factory: ProviderFactory<DriverNode>,
    host_executor: Arc<EthHostExecutor>,
    hub: Arc<WitnessHub>,
) -> eyre::Result<Vec<u8>> {
    let block_number = fetched.block_number;
    let fetch_ms = fetched.fetch_ms;

    if let Some(cached) = hub.get_witness(block_number).await {
        info!(
            block_number,
            payload_bytes = cached.payload.len() as u64,
            fetch_ms,
            "Block re-witness served from cold store"
        );
        return Ok(cached.payload);
    }

    let FetchedBlock { block_number, alloy_block, fetch_ms } = fetched;
    let t_total_start = Instant::now();

    let prim_block =
        <reth_ethereum_primitives::EthPrimitives as IntoPrimitives<Ethereum>>::into_primitive_block(
            alloy_block,
        );

    let parent_state_root = factory
        .header_by_number(block_number - 1)
        .map_err(|e| eyre!("header_by_number({}): {e}", block_number - 1))?
        .ok_or_else(|| eyre!("missing header N-1 during re-witness of block {block_number}"))?
        .state_root;

    let t_witness = Instant::now();
    let input = tokio::task::spawn_blocking(move || -> eyre::Result<_> {
        let read_view =
            BlockchainProvider::new(factory).map_err(|e| eyre!("BlockchainProvider::new: {e}"))?;
        host_executor
            .execute_exex_with_block(prim_block, parent_state_root, read_view, None)
            .map_err(|e| eyre!("execute_exex_with_block (rewitness): {e}"))
    })
    .await
    .map_err(|e| eyre!("rewitness_phase join: {e}"))??;
    let witness_ms = t_witness.elapsed().as_millis() as u64;

    let t_ser = Instant::now();
    let payload = match tokio::task::spawn_blocking(move || bincode::serialize(&input)).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(e)) => {
            error!(block_number, err = %e, "bincode serialize failed (rewitness)");
            return Err(eyre!("bincode: {e}"));
        }
        Err(e) => {
            error!(block_number, err = %e, "serialize task panicked (rewitness)");
            return Err(eyre!("serialize task: {e}"));
        }
    };
    let serialize_ms = t_ser.elapsed().as_millis() as u64;

    info!(
        block_number,
        total_ms = t_total_start.elapsed().as_millis() as u64,
        fetch_ms,
        witness_ms,
        serialize_ms,
        payload_bytes = payload.len() as u64,
        "Block re-witness built"
    );

    Ok(payload)
}

/// Boot-time unwind entry. `target` is interpreted with reth-CLI semantic:
/// `UNWIND_TO_BLOCK=N` removes N and everything above (new MDBX tip = N-1).
/// Bounds checks short-circuit (warn/info + skip, never error) for:
///   - `target == 0`       — would underflow `N-1`.
///   - `target > mdbx_tip` — likely typo; silent no-op with warn.
///   - `target == mdbx_tip` — already aligned.
///
/// Must be called exactly once, between `open_writable_factory` and
/// `Driver::new`. Fatal on MDBX or cold-store failure — operator restarts
/// with env still set and the next boot retries.
pub(crate) async fn unwind_to(
    factory: ProviderFactory<DriverNode>,
    hub: Arc<WitnessHub>,
    target: u64,
) -> eyre::Result<()> {
    let mdbx_tip_before =
        factory.best_block_number().map_err(|e| eyre!("unwind: best_block_number: {e}"))?;

    if target == 0 {
        warn!(target, "UNWIND_TO_BLOCK=0 is not supported (minimum is 1) — skipping");
        return Ok(());
    }
    if target > mdbx_tip_before {
        warn!(target, mdbx_tip_before, "UNWIND_TO_BLOCK above current tip — skipping");
        return Ok(());
    }
    if target == mdbx_tip_before {
        info!(target, "UNWIND_TO_BLOCK matches current tip — skipping");
        return Ok(());
    }

    // reth-CLI semantic: `UNWIND_TO_BLOCK=N` means N is REMOVED along with
    // everything above. The provider API keeps the argument block, so we pass
    // N-1 to get the intended "strictly below N" retention.
    let keep = target - 1;
    info!(target, keep, mdbx_tip_before, "UNWIND_TO_BLOCK — starting MDBX + static_files unwind");

    let factory_clone = factory.clone();
    tokio::task::spawn_blocking(move || -> eyre::Result<()> {
        let provider_rw =
            factory_clone.provider_rw().map_err(|e| eyre!("unwind: provider_rw: {e}"))?;
        provider_rw
            .remove_block_and_execution_above(keep)
            .map_err(|e| eyre!("unwind: remove_block_and_execution_above({keep}): {e}"))?;
        provider_rw.commit().map_err(|e| eyre!("unwind: provider_rw.commit: {e}"))?;
        Ok(())
    })
    .await
    .map_err(|e| eyre!("unwind: spawn_blocking join: {e}"))??;

    let mdbx_tip_after = factory
        .best_block_number()
        .map_err(|e| eyre!("unwind: best_block_number post-commit: {e}"))?;

    let (cold_removed_count, cold_bytes_freed) =
        hub.unwind_above(keep).await.map_err(|e| eyre!("unwind: cold: {e}"))?;

    info!(
        target,
        mdbx_tip_before,
        mdbx_tip_after,
        cold_removed_count,
        cold_bytes_freed,
        "Unwind complete — remember to UNSET UNWIND_TO_BLOCK before next restart"
    );
    Ok(())
}
