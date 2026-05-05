//! L1 rollup contract bindings and helpers — the read+write surface for the
//! Fluent rollup contract on L1. Used by `bin/witness-orchestrator` (read +
//! write) and `bin/proxy` (read only, for batch metadata lookup).
//!
//! What lives here:
//! - sol! ABI: all on-chain events (lifecycle, challenge, rewards) and the `preconfirmBatch`
//!   function.
//! - Read helpers: `resolve_l2_start_checkpoint`, `fetch_batch_range`.
//! - Write helpers: `submit_preconfirmation`.
//!
//! What does NOT live here (intentionally):
//! - Polling loop — orchestrator-specific.
//! - L1Event enum — orchestrator-specific event channel type.
//! - NitroVerifier ABI — see `nitro_verifier` submodule.

pub mod nitro_verifier;

pub use nitro_verifier::is_key_registered;

use std::sync::atomic::{AtomicU64, Ordering};

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_network::TxSigner;
use alloy_primitives::{Address, Bytes, FixedBytes, Signature, TxKind, B256, U256};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types::{Filter, TransactionRequest};
use alloy_sol_types::{sol, SolCall, SolEvent};
use eyre::{eyre, Result};
use tokio::sync::Mutex as AsyncMutex;
use tracing::{info, warn};

// =====================================================================
// Contract ABI (Rollup.sol @ release/v1.0.0)
// =====================================================================

sol! {
    // ============ Batch lifecycle ============

    /// Emitted by `commitBatch` — declares a new batch with its batch root,
    /// first/last block hashes, block count, and expected blob count.
    event BatchCommitted(
        uint256 indexed batchIndex,
        bytes32 batchRoot,
        bytes32 fromBlockHash,
        bytes32 toBlockHash,
        uint24 numberOfBlocks,
        uint256 expectedBlobs
    );

    /// Emitted each time the sequencer submits blob hashes for a batch.
    event BatchBlobsSubmitted(
        uint256 indexed batchIndex,
        uint256 numBlobs,
        uint256 totalBlobs
    );

    /// Emitted when all expected blobs are in DA and the batch moves to Submitted.
    event BatchSubmitted(uint256 indexed batchIndex);

    /// Emitted when Nitro preconfirmation is committed for a batch.
    event BatchPreconfirmed(
        uint256 indexed batchIndex,
        address indexed verifierContract,
        address indexed verifier
    );

    /// Emitted when a batch is permanently finalized after the challenge period.
    event BatchFinalized(uint256 indexed batchIndex);

    /// Emitted when admin force-reverts batches from a given index onward.
    event BatchReverted(uint256 indexed fromBatchIndex);

    // ============ Challenge lifecycle ============

    /// Emitted when a challenger disputes a block in a preconfirmed batch.
    event BlockChallenged(
        uint256 indexed batchIndex,
        bytes32 indexed commitment,
        address indexed challenger
    );

    /// Emitted when a challenger opens a batch-root validity dispute.
    event BatchRootChallenged(uint256 indexed batchIndex);

    /// Emitted when a prover resolves a challenge with Nitro + SP1 proof.
    event ChallengeResolved(
        uint256 indexed batchIndex,
        bytes32 indexed commitment,
        address indexed prover
    );

    /// Emitted when a batch root challenge is resolved.
    event BatchRootChallengeResolved(
        uint256 indexed batchIndex,
        address indexed prover
    );

    // ============ Rewards ============

    /// Emitted when a challenger claims their reward (deposit + incentive fee).
    event ChallengerRewardClaimed(address indexed challenger, uint256 amount);

    /// Emitted when a prover claims their proof reward.
    event ProofRewardClaimed(address indexed prover, uint256 amount);

    // ============ Types ============

    /// Mirrors `enum BatchStatus` in `IRollupTypes.sol`. Ordinal values are
    /// consensus-critical — any reorder here would silently flip on-chain
    /// status comparisons.
    enum BatchStatus {
        None,
        Committed,
        Submitted,
        Preconfirmed,
        Challenged,
        Finalized
    }

    /// Mirrors `struct BatchRecord` in `IRollupTypes.sol`. Only the fields
    /// actually read by this crate are annotated in comments; the rest are
    /// kept in-struct so decoding matches the contract layout.
    struct BatchRecord {
        bytes32 batchRoot;
        uint32 acceptedAtBlock;
        uint8 expectedBlobs;
        BatchStatus status;
        uint64 sentMessageCursorStart;
        uint24 submitBlobsWindowSnapshot;
        uint24 preconfirmationWindowSnapshot;
        uint24 challengeWindowSnapshot;
        uint24 finalizationDelaySnapshot;
        uint24 numberOfBlocks;
        bytes32 toBlockHash;
    }

    /// Mirrors `struct L2BlockHeader` in `IRollupTypes.sol`. Field order
    /// is consensus-critical — `_computeCommitment` keccaks the four
    /// `bytes32` fields in struct-declaration order. `depositCount` is
    /// in the struct but NOT part of the commitment hash.
    struct L2BlockHeader {
        bytes32 previousBlockHash;
        bytes32 blockHash;
        bytes32 withdrawalRoot;
        bytes32 depositRoot;
        uint16 depositCount;
    }

    /// Mirrors `struct L2BlockHeaderV1` in `IRollupTypes.sol` — the compact
    /// header passed to `resolveBatchRootChallenge`. Drops `previousBlockHash`
    /// (the contract chains it from `previousBatch.toBlockHash` storage) and
    /// `depositCount` (not part of the leaf hash and not consumed by V1
    /// resolve). Field order is consensus-critical: `_calculateBatchRootV1`
    /// keccaks `prevBlockHash || blockHash || withdrawalRoot || depositRoot`
    /// — same layout as V0, only the `prevBlockHash` source moves off-call.
    struct L2BlockHeaderV1 {
        bytes32 blockHash;
        bytes32 withdrawalRoot;
        bytes32 depositRoot;
    }

    /// Mirrors `MerkleTree.MerkleProof` in `MerkleTree.sol`. `nonce` is
    /// the leaf index; `proof` is a packed sequence of 32-byte sibling
    /// hashes from leaf to root.
    struct MerkleProof {
        uint256 nonce;
        bytes proof;
    }

    // ============ Functions ============

    /// Submit enclave signature to L1, proving batch validity.
    function preconfirmBatch(
        address nitroVerifier,
        uint256 batchIndex,
        bytes signature
    ) external;

    /// View: full batch record, including current lifecycle status and the
    /// L1 block at which the batch was committed. Used by the orchestrator
    /// to detect already-preconfirmed / finalized batches on restart,
    /// avoiding a deterministic revert loop when dispatch retries a batch
    /// whose state moved past `Submitted` while the orchestrator was down.
    function getBatch(uint256 batchIndex) external view returns (BatchRecord memory);

    // ============ Custom errors (for revert-decoding in pre-broadcast simulation) ============

    error InvalidBatchRoot(bytes32 expected, bytes32 actual);
    error InvalidBlockSequence(uint256 index, bytes32 expected, bytes32 actual);
    error WrongPreviousBlockHash(bytes32 expected, bytes32 actual);
    error InvalidLastBlockHash(bytes32 expected, bytes32 actual);
    error InvalidBlockProof();
    error BlockNotChallenged(bytes32 commitment);
    error BlockAlreadyProven(bytes32 commitment);
    error BatchRootNotChallenged(uint256 batchIndex);
    error BatchRootAlreadyProven(uint256 batchIndex);
    error InvalidBatchStatus(uint256 batchIndex, uint8 status);
    error RollupCorrupted();
    error ChallengeResolutionTooLate(uint256 batchIndex, uint256 deadline, uint256 blockNumber);
    error InvalidBatchIndex(uint256 received, uint256 expected);
    // OpenZeppelin v5 — surfaced when the L1 signer lacks PROVER_ROLE / similar.
    error AccessControlUnauthorizedAccount(address account, bytes32 neededRole);
    // OpenZeppelin v5 Pausable — surfaced when EMERGENCY_ROLE has paused the contract.
    error EnforcedPause();
    // Rollup-side challenge-open / lifecycle reverts — useful for operator log decoding even
    // though the resolver only hits the resolve* paths directly.
    error BatchAlreadyChallenged(uint256 batchIndex);
    error BatchRootChallengeOpen(uint256 batchIndex);
    error IncorrectChallengeDeposit(uint256 expected, uint256 actual);
    error ChallengeTooLate(uint256 batchIndex);
    error BatchAlreadyFinalized(uint256 batchIndex);

    /// Resolve a single-block dispute with an SP1 Groth16 proof. The
    /// contract re-derives the commitment from `blockHeader`, verifies
    /// `blockProof` against the batch's `batchRoot`, then calls
    /// `ISP1Verifier.verifyProof(...)`.
    function resolveBlockChallenge(
        uint256 batchIndex,
        L2BlockHeader blockHeader,
        MerkleProof blockProof,
        bytes sp1Proof
    ) external;

    /// Resolve a batch-root dispute. The contract reads
    /// `previousBatch.toBlockHash` from storage and runs
    /// `_calculateBatchRootV1(prevBlockHash, blockHeaders)` over the
    /// V1-shaped headers, chaining `prevBlockHash` forward via each
    /// header's `blockHash`. Reverts with `InvalidBatchRoot` if the
    /// reconstruction does not match the stored `batch.batchRoot`.
    function resolveBatchRootChallenge(
        uint256 batchIndex,
        L2BlockHeaderV1[] blockHeaders
    ) external;
}

// =====================================================================
// Read helpers
// =====================================================================

/// Walk `BatchCommitted` events from `l1_deploy_block` until the event for
/// `batch_id` is found, then derive the L2 starting block from its
/// `fromBlockHash` field.
///
/// Sequencer convention: `fromBlockHash` is the hash of the **last block of
/// the previous batch** (exclusive lower bound), `toBlockHash` is the hash of
/// the **last block of the current batch** (inclusive upper bound). The batch
/// covers `(fromBlockHash, toBlockHash]` = `[fromBlockHash.number + 1,
/// toBlockHash.number]`. So `l2_from_block = fromBlockHash.number + 1`, and
/// `numberOfBlocks = toBlockHash.number - fromBlockHash.number`.
///
/// Returns `(l2_from_block, l1_event_block, num_blocks)`:
/// - `l2_from_block`: first L2 block in the batch
/// - `l1_event_block`: L1 block containing the `BatchCommitted` event
/// - `num_blocks`: number of L2 block headers in this batch
///
/// Rejects `batch_id == 0` — batch 0 is the synthetic genesis batch and
/// cannot be reproved.
///
/// Note: this is O(batch_id) on cold start. Callers should treat it as a
/// rare manual operation (e.g., explicit `L1_START_BATCH_ID`).
pub async fn resolve_l2_start_checkpoint(
    l1_provider: &RootProvider,
    l2_provider: &RootProvider,
    contract_addr: Address,
    batch_id: u64,
    l1_deploy_block: u64,
) -> Result<(u64, u64, u64)> {
    if batch_id == 0 {
        return Err(eyre!(
            "L1_START_BATCH_ID must be >= 1. Batch 0 is the synthetic genesis \
             batch and cannot be reproved; use batch_id=1 to start at the \
             first user-facing batch."
        ));
    }

    let latest = l1_provider
        .get_block_number()
        .await
        .map_err(|e| eyre!("Failed to get latest L1 block: {e}"))?;

    const PAGE: u64 = 50_000;
    const SCAN_DELAY: std::time::Duration = std::time::Duration::from_millis(500);

    let mut target: Option<(u64, u64, B256)> = None; // (l1_event_block, num_blocks, from_block_hash)
    let mut current = l1_deploy_block;

    let mut anchor: Option<FixedBytes<32>> = None;

    'outer: while current <= latest {
        let page_end = (current + PAGE - 1).min(latest);
        let filter = Filter::new()
            .address(contract_addr)
            .event_signature(vec![BatchCommitted::SIGNATURE_HASH])
            .from_block(current)
            .to_block(page_end);
        let logs = l1_provider
            .get_logs(&filter)
            .await
            .map_err(|e| eyre!("eth_getLogs [{current}..{page_end}] failed: {e}"))?;

        for log in logs {
            let topic0 = log.topic0().copied().unwrap_or_default();
            let (idx, num_blocks_u64, anchor_candidate) =
                if topic0 == BatchCommitted::SIGNATURE_HASH {
                    let ev = BatchCommitted::decode_log_data(&log.inner.data)
                        .map_err(|e| eyre!("decode BatchCommitted v1: {e}"))?;
                    let idx: u64 = ev
                        .batchIndex
                        .try_into()
                        .map_err(|_| eyre!("batchIndex overflow: {}", ev.batchIndex))?;
                    let nb: u64 = ev
                        .numberOfBlocks
                        .try_into()
                        .map_err(|_| eyre!("numberOfBlocks overflow: {}", ev.numberOfBlocks))?;
                    (idx, nb, ev.fromBlockHash)
                } else {
                    continue;
                };

            if idx == batch_id {
                let l1_block = log
                    .block_number
                    .ok_or_else(|| eyre!("BatchCommitted log missing block_number"))?;
                target = Some((l1_block, num_blocks_u64, B256::ZERO));
                anchor = Some(anchor_candidate);
                break 'outer;
            }
        }

        current = page_end + 1;
        if current <= latest {
            tokio::time::sleep(SCAN_DELAY).await;
        }
    }

    let (l1_block, num_blocks, _) = target.ok_or_else(|| {
        eyre!(
            "BatchCommitted for batch {batch_id} not found in L1 blocks \
             [{l1_deploy_block}..{latest}]. \
             Ensure L1_ROLLUP_DEPLOY_BLOCK is ≤ the block where batch {batch_id} was committed. \
             If the block range is correct, the deployed Rollup contract's ABI \
             may have drifted from this binding — verify the BatchCommitted \
             topic hash against the release the contract was deployed from."
        )
    })?;
    let anchor = anchor.expect("anchor set whenever target is set");

    let (anchor_hash, l2_from_block) = {
        let h = anchor;

        // `fromBlockHash` is the LAST block of the PREVIOUS batch
        // (exclusive lower bound), so the first block of THIS batch is `n + 1`.
        let n = l2_provider
            .get_block_by_hash(anchor)
            .await
            .map_err(|e| eyre!("eth_getBlockByHash({h}) on L2: {e}"))?
            .ok_or_else(|| {
                eyre!(
                    "L2 block with hash {h} (from BatchCommitted.fromBlockHash \
                         for batch {batch_id}) not found — L2 RPC may be pointing \
                         at the wrong chain or be missing history."
                )
            })?
            .header
            .number;
        (h, n + 1)
    };
    let from_block_hash = anchor_hash;

    info!(
        batch_id,
        %from_block_hash,
        l2_from_block,
        l2_to_block = l2_from_block + num_blocks.saturating_sub(1),
        num_blocks,
        l1_block,
        "Resolved L2 start checkpoint"
    );

    Ok((l2_from_block, l1_block, num_blocks))
}

/// Resolve `(from_block, to_block)` for a given `batch_id` using L1 + L2
/// reads. Used by `bin/proxy` to map a challenge request's `batch_index` →
/// L2 block range without requiring the caller to know it.
pub async fn fetch_batch_range(
    l1_provider: &RootProvider,
    l2_provider: &RootProvider,
    contract_addr: Address,
    batch_id: u64,
    l1_deploy_block: u64,
) -> Result<(u64, u64)> {
    let (l2_from_block, _l1_event_block, num_blocks) = resolve_l2_start_checkpoint(
        l1_provider,
        l2_provider,
        contract_addr,
        batch_id,
        l1_deploy_block,
    )
    .await?;
    let to_block = l2_from_block + num_blocks - 1;
    Ok((l2_from_block, to_block))
}

/// Resolved L1 identity of a `BatchPreconfirmed` event for a given batch.
/// Populated by [`find_batch_preconfirm_event`] and consumed by the
/// orchestrator's startup-reconciliation path to seed `dispatched_batches`
/// with the winning transaction's coordinates (so the finalization ticker
/// can drive the batch to completion).
#[derive(Debug, Clone, Copy)]
pub struct BatchPreconfirmInfo {
    pub tx_hash: B256,
    pub l1_block: u64,
}

/// Canonical lifecycle status ordinals for `enum BatchStatus` in
/// `IRollupTypes.sol`. Kept as `u8` constants (not an enum) to avoid coupling
/// callers to the `sol!`-generated type's local module path.
pub mod batch_status {
    pub const NONE: u8 = 0;
    pub const COMMITTED: u8 = 1;
    pub const SUBMITTED: u8 = 2;
    pub const PRECONFIRMED: u8 = 3;
    pub const CHALLENGED: u8 = 4;
    pub const FINALIZED: u8 = 5;
}

/// Minimal subset of `BatchRecord` the orchestrator needs for on-chain
/// reconciliation: current lifecycle status, the L1 block at which the
/// batch was first committed (lower bound for a targeted event scan),
/// and the snapshot of `challengeWindow` taken at commitBatch time
/// (used to compute the per-row challenge deadline locally).
#[derive(Debug, Clone, Copy)]
pub struct BatchOnChain {
    pub status: u8,
    pub accepted_at_block: u64,
    pub challenge_window_snapshot: u64,
}

/// View-call `getBatch(batchIndex)` and project the fields used by the
/// orchestrator's startup-reconciliation / pre-flight / challenge paths.
/// One RPC round trip.
pub async fn get_batch_on_chain(
    l1_provider: &impl Provider,
    contract_addr: Address,
    batch_index: u64,
) -> Result<BatchOnChain> {
    let call = getBatchCall { batchIndex: U256::from(batch_index) };
    let input = Bytes::from(call.abi_encode());
    let req = TransactionRequest {
        to: Some(contract_addr.into()),
        input: input.into(),
        ..Default::default()
    };
    let raw = l1_provider
        .call(req)
        .await
        .map_err(|e| eyre!("eth_call getBatch({batch_index}) failed: {e}"))?;
    let decoded = getBatchCall::abi_decode_returns(&raw)
        .map_err(|e| eyre!("decode getBatch({batch_index}) return: {e}"))?;
    let challenge_window_snapshot: u64 =
        decoded.challengeWindowSnapshot.try_into().map_err(|_| {
            eyre!("challengeWindowSnapshot overflow: {}", decoded.challengeWindowSnapshot)
        })?;
    Ok(BatchOnChain {
        status: decoded.status as u8,
        accepted_at_block: u64::from(decoded.acceptedAtBlock),
        challenge_window_snapshot,
    })
}

/// Scan L1 for the `BatchPreconfirmed(batchIndex=…)` event in the given
/// block range. Returns the first matching log's transaction hash and block
/// number, or `None` if no such event exists in the window.
///
/// Used by the orchestrator when a pre-flight status check reveals that the
/// target batch is already `Preconfirmed` or `Finalized` on L1 — the stored
/// `l1_checkpoint` may have already advanced past the event, so the
/// live-listener path will never replay it.
pub async fn find_batch_preconfirm_event(
    l1_provider: &impl Provider,
    contract_addr: Address,
    batch_index: u64,
    from_l1_block: u64,
    to_l1_block: u64,
) -> Result<Option<BatchPreconfirmInfo>> {
    if from_l1_block > to_l1_block {
        return Ok(None);
    }
    let topic1 = B256::from(U256::from(batch_index));
    let filter = Filter::new()
        .address(contract_addr)
        .event_signature(BatchPreconfirmed::SIGNATURE_HASH)
        .topic1(topic1)
        .from_block(from_l1_block)
        .to_block(to_l1_block);
    let logs = l1_provider
        .get_logs(&filter)
        .await
        .map_err(|e| eyre!("eth_getLogs BatchPreconfirmed[{batch_index}] failed: {e}"))?;
    let Some(log) = logs.into_iter().next() else { return Ok(None) };
    let tx_hash = log
        .transaction_hash
        .ok_or_else(|| eyre!("BatchPreconfirmed[{batch_index}] log missing transaction_hash"))?;
    let l1_block = log
        .block_number
        .ok_or_else(|| eyre!("BatchPreconfirmed[{batch_index}] log missing block_number"))?;
    Ok(Some(BatchPreconfirmInfo { tx_hash, l1_block }))
}

// =====================================================================
// Write helpers (RBF-aware)
// =====================================================================

/// Same fields as [`RollupTxTemplate`] except `nonce`. Returned by the
/// `prepare_*_tx` builders so callers can run their nonce allocation
/// AFTER the gas-estimation / pre-broadcast simulation steps that may
/// revert with terminal errors (`AccessControlUnauthorizedAccount`,
/// `InvalidBatchStatus`, etc.). Convert with [`Self::with_nonce`] just
/// before broadcast.
#[derive(Debug, Clone)]
pub struct RollupTxPartial {
    pub to: Address,
    pub input: Bytes,
    pub gas_limit: u64,
    pub chain_id: u64,
    /// Log correlation id only — never read from the calldata.
    pub batch_index: u64,
    /// Tag included in broadcast logs (`"preconfirm"`,
    /// `"resolve_block_challenge"`, `"resolve_batch_root_challenge"`).
    pub tx_kind: &'static str,
}

impl RollupTxPartial {
    /// Attach an allocated nonce to produce a ready-to-sign template.
    pub fn with_nonce(self, nonce: u64) -> RollupTxTemplate {
        let RollupTxPartial { to, input, gas_limit, chain_id, batch_index, tx_kind } = self;
        RollupTxTemplate { to, input, nonce, gas_limit, chain_id, batch_index, tx_kind }
    }
}

/// Immutable metadata for an in-flight rollup-write transaction. Produced
/// by [`RollupTxPartial::with_nonce`] just before the first broadcast and
/// reused across RBF bumps — only `max_fee_per_gas` /
/// `max_priority_fee_per_gas` change on each rebroadcast.
#[derive(Debug, Clone)]
pub struct RollupTxTemplate {
    pub to: Address,
    pub input: Bytes,
    pub nonce: u64,
    pub gas_limit: u64,
    pub chain_id: u64,
    /// Log correlation id only — never read from the calldata.
    pub batch_index: u64,
    /// Tag included in broadcast logs (`"preconfirm"`,
    /// `"resolve_block_challenge"`, `"resolve_batch_root_challenge"`).
    pub tx_kind: &'static str,
}

/// `estimate * 1.2` — industry-standard +20% padding over `eth_estimateGas`.
/// See `~/.claude/standards/solidity/gotchas.md` "Never use raw eth_estimateGas
/// as gas_limit". Saturating: Rust's `f64 as u64` cast saturates on `+inf`
/// since 1.45. Pulled out for unit testing.
pub fn apply_gas_buffer(estimate: u64) -> u64 {
    (estimate as f64 * 1.2) as u64
}

/// Build the calldata + gas-limit for a `preconfirmBatch` dispatch.
/// Returns a [`RollupTxPartial`] — the caller attaches a nonce via
/// [`RollupTxPartial::with_nonce`] just before broadcast, after pulling
/// from a shared [`NonceAllocator`].
pub async fn prepare_preconfirm_tx(
    provider: &impl Provider,
    contract_addr: Address,
    nitro_verifier_addr: Address,
    batch_index: u64,
    signature: Vec<u8>,
    signer: Address,
) -> Result<RollupTxPartial> {
    let call = preconfirmBatchCall {
        nitroVerifier: nitro_verifier_addr,
        batchIndex: U256::from(batch_index),
        signature: Bytes::from(signature),
    };
    let mut partial = build_partial_calldata(
        provider,
        contract_addr,
        batch_index,
        "preconfirm",
        call.abi_encode(),
    )
    .await?;
    finalize_partial(provider, &mut partial, signer).await?;
    Ok(partial)
}

/// Build calldata for `resolveBlockChallenge`. Returns a calldata-only
/// [`RollupTxPartial`] (`gas_limit == 0`); caller MUST run pre-broadcast
/// simulation and then [`finalize_partial`] before [`RollupTxPartial::with_nonce`].
///
/// Splitting calldata-only from `eth_estimateGas` lets the caller's
/// `eth_call` simulation surface terminal contract reverts (missing
/// `PROVER_ROLE`, paused contract, corrupted rollup, etc.) BEFORE we
/// pay for `estimate_gas` — the simulation result is the authoritative
/// signal, and a permanent revert classifies as terminal `Failed`
/// instead of looping forever.
pub async fn prepare_resolve_block_challenge_tx(
    provider: &impl Provider,
    contract_addr: Address,
    batch_index: u64,
    block_header: L2BlockHeader,
    block_proof: MerkleProof,
    sp1_proof: Vec<u8>,
) -> Result<RollupTxPartial> {
    let call = resolveBlockChallengeCall {
        batchIndex: U256::from(batch_index),
        blockHeader: block_header,
        blockProof: block_proof,
        sp1Proof: Bytes::from(sp1_proof),
    };
    build_partial_calldata(
        provider,
        contract_addr,
        batch_index,
        "resolve_block_challenge",
        call.abi_encode(),
    )
    .await
}

/// Build calldata for `resolveBatchRootChallenge`. No SP1 proof; the
/// contract re-derives the merkle root from `block_headers` chained
/// against `previousBatch.toBlockHash` from storage.
///
/// Returns a calldata-only [`RollupTxPartial`] (`gas_limit == 0`); see
/// [`prepare_resolve_block_challenge_tx`] for the rationale.
pub async fn prepare_resolve_batch_root_challenge_tx(
    provider: &impl Provider,
    contract_addr: Address,
    batch_index: u64,
    block_headers: Vec<L2BlockHeaderV1>,
) -> Result<RollupTxPartial> {
    let call = resolveBatchRootChallengeCall {
        batchIndex: U256::from(batch_index),
        blockHeaders: block_headers,
    };
    build_partial_calldata(
        provider,
        contract_addr,
        batch_index,
        "resolve_batch_root_challenge",
        call.abi_encode(),
    )
    .await
}

/// Calldata + chain_id only — no `eth_estimateGas`. The returned partial
/// has `gas_limit == 0` until [`finalize_partial`] is called.
async fn build_partial_calldata(
    provider: &impl Provider,
    contract_addr: Address,
    batch_index: u64,
    tx_kind: &'static str,
    encoded_call: Vec<u8>,
) -> Result<RollupTxPartial> {
    let chain_id = provider.get_chain_id().await.map_err(|e| eyre!("get_chain_id failed: {e}"))?;
    Ok(RollupTxPartial {
        to: contract_addr,
        input: Bytes::from(encoded_call),
        gas_limit: 0,
        chain_id,
        batch_index,
        tx_kind,
    })
}

/// Run `eth_estimateGas` against `partial.input` and populate
/// `partial.gas_limit`. MUST be called after pre-broadcast simulation
/// succeeds and before [`RollupTxPartial::with_nonce`] for the resolve
/// path; preconfirm callers run it inline at the end of
/// [`prepare_preconfirm_tx`] since their pre-flight already verified
/// contract state.
pub async fn finalize_partial(
    provider: &impl Provider,
    partial: &mut RollupTxPartial,
    signer: Address,
) -> Result<()> {
    let est_req = TransactionRequest {
        from: Some(signer),
        to: Some(partial.to.into()),
        input: partial.input.clone().into(),
        ..Default::default()
    };
    let estimate =
        provider.estimate_gas(est_req).await.map_err(|e| eyre!("estimate_gas failed: {e}"))?;
    partial.gas_limit = apply_gas_buffer(estimate);
    Ok(())
}

/// Returns true when the JSON-RPC error string from `send_raw_transaction`
/// indicates the signed nonce is already consumed by a landed or pending
/// transaction. Used by the RBF worker to decide whether to resync the
/// allocator / harvest the receipt of the winning hash.
pub fn is_nonce_too_low_error(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    lower.contains("nonce too low") ||
        lower.contains("nonce_too_low") ||
        lower.contains("invalid nonce") ||
        lower.contains("oldnonce") ||
        lower.contains("old nonce")
}

// =====================================================================
// Nonce allocator
// =====================================================================

/// Single writer for L1 signer nonces across the orchestrator.
///
/// Motivation: `provider.get_transaction_count(signer).pending()` is the only
/// RPC-derivable "next nonce" value, but it is not a reliable single source of
/// truth when several workers share one signer:
///
/// * Resume workers at startup each own a persisted nonce from a prior process lifetime; they may
///   still be rebroadcasting into the mempool.
/// * Load-balanced RPC endpoints can return stale `pending` counts that do not yet reflect those
///   resume-workers' pending txs.
/// * Mempool evictions / reorgs can briefly make `pending` non-monotonic.
///
/// Any of those drifts, combined with a concurrent fresh dispatch calling
/// `get_transaction_count(pending)`, surfaces as a "nonce too low" error on
/// broadcast — the symptom the user saw in production.
///
/// This allocator centralizes nonce assignment:
///
/// * One `AtomicU64` holds the next-to-hand-out nonce; `allocate()` is a single `fetch_add` so
///   concurrent callers never observe the same nonce.
/// * [`Self::bootstrap`] seeds it with `max(rpc_pending, max_stored_nonce+1)` so already-dispatched
///   (resume) rows are respected.
/// * [`Self::release`] returns an unused nonce on pre-broadcast failure via a tail-CAS — safe in
///   the common case (one fresh dispatch gated by `dispatching_batch`).
/// * [`Self::resync`] is a coarse recovery for the rare case when our view drifted past RPC (e.g.,
///   after a reorg that evicted our pending tx); it rereads `pending` under a lock and jumps the
///   counter forward if RPC is ahead.
#[derive(Debug)]
pub struct NonceAllocator {
    next: AtomicU64,
    resync_lock: AsyncMutex<()>,
}

impl NonceAllocator {
    /// Seed the allocator at orchestrator startup. `stored_floor` is the
    /// smallest nonce that is safe to hand out next — typically
    /// `max(persisted_dispatched_nonce) + 1`, or `None` when no
    /// dispatched rows exist. The effective start is
    /// `max(rpc_pending, stored_floor)`.
    ///
    /// Returns `(start, pending)` so the caller can update both the
    /// allocator-next gauge and the L1-pending gauge from one call.
    pub async fn bootstrap(
        provider: &impl Provider,
        signer: Address,
        stored_floor: Option<u64>,
    ) -> Result<(Self, u64)> {
        let pending =
            provider.get_transaction_count(signer).pending().await.map_err(|e| {
                eyre!("NonceAllocator::bootstrap: get_transaction_count(pending): {e}")
            })?;
        let start = pending.max(stored_floor.unwrap_or(0));
        info!(
            rpc_pending = pending,
            stored_floor = stored_floor.unwrap_or(0),
            start,
            "NonceAllocator bootstrapped"
        );
        let allocator = Self { next: AtomicU64::new(start), resync_lock: AsyncMutex::new(()) };
        Ok((allocator, pending))
    }

    /// Hand out the next nonce. Monotonic; never returns the same value twice.
    pub fn allocate(&self) -> u64 {
        self.next.fetch_add(1, Ordering::SeqCst)
    }

    /// Same as [`Self::release_with_outcome`] but discards the result.
    /// Use when the caller does not record leak metrics.
    pub fn release(&self, nonce: u64) {
        let _ = self.release_with_outcome(nonce);
    }

    /// Attempt to reclaim `nonce` when a pre-broadcast step failed (e.g.,
    /// shutdown signal between allocate and broadcast). Only succeeds when
    /// `nonce + 1` is still the head of the counter — if another allocation
    /// raced ahead, returns `false` and the nonce is permanently un-issued.
    /// Callers that observe `false` should increment a leak metric: a
    /// non-zero leak counter signals a regression of the defer-allocate
    /// invariant (allocation should run AFTER all RPC-revert-prone steps,
    /// so the `release` window is bounded to a tiny cancel race).
    pub fn release_with_outcome(&self, nonce: u64) -> bool {
        self.next.compare_exchange(nonce + 1, nonce, Ordering::SeqCst, Ordering::SeqCst).is_ok()
    }

    /// Reread `pending` from RPC under a lock and advance the counter past
    /// it. Used after a broadcast failure with "nonce too low": the chain has
    /// moved beyond what we allocated, so future allocations must not try to
    /// reuse any nonce below RPC's current pending.
    ///
    /// Returns `(new_next, pending)` — `new_next` is the post-resync counter
    /// value, `pending` is the RPC reading used to compute it.
    pub async fn resync(&self, provider: &impl Provider, signer: Address) -> Result<(u64, u64)> {
        let _guard = self.resync_lock.lock().await;
        let pending =
            provider.get_transaction_count(signer).pending().await.map_err(|e| {
                eyre!("NonceAllocator::resync: get_transaction_count(pending): {e}")
            })?;
        let current = self.next.load(Ordering::SeqCst);
        let new = pending.max(current);
        if new != current {
            warn!(
                old = current,
                new,
                rpc_pending = pending,
                "NonceAllocator resynced past stale local view"
            );
            self.next.store(new, Ordering::SeqCst);
        }
        Ok((new, pending))
    }

    /// Peek the next nonce that would be handed out. Test/diagnostic only.
    #[doc(hidden)]
    pub fn peek(&self) -> u64 {
        self.next.load(Ordering::SeqCst)
    }
}

/// Sign + broadcast one EIP-1559 transaction with explicit nonce + fees.
/// Returns the tx hash. Does NOT wait for a receipt — the caller is
/// responsible for polling and, if needed, bumping fees + rebroadcasting.
pub async fn broadcast_rollup_tx(
    provider: &impl Provider,
    signer: &(dyn TxSigner<Signature> + Send + Sync),
    template: &RollupTxTemplate,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
) -> Result<B256> {
    let mut tx = TxEip1559 {
        chain_id: template.chain_id,
        nonce: template.nonce,
        gas_limit: template.gas_limit,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        to: TxKind::Call(template.to),
        value: U256::ZERO,
        access_list: Default::default(),
        input: template.input.clone(),
    };
    let sig = signer
        .sign_transaction(&mut tx)
        .await
        .map_err(|e| eyre!("sign_transaction failed: {e}"))?;
    let envelope = TxEnvelope::Eip1559(tx.into_signed(sig));
    let mut buf = Vec::new();
    envelope.encode_2718(&mut buf);

    let pending = provider
        .send_raw_transaction(&buf)
        .await
        .map_err(|e| eyre!("send_raw_transaction failed: {e}"))?;
    let tx_hash = *pending.tx_hash();
    info!(
        %tx_hash,
        tx_kind = template.tx_kind,
        batch_index = template.batch_index,
        nonce = template.nonce,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        "broadcast_rollup_tx"
    );
    Ok(tx_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_nonce_too_low_matches_common_variants() {
        assert!(is_nonce_too_low_error("nonce too low"));
        assert!(is_nonce_too_low_error("Nonce Too Low: expected 42"));
        assert!(is_nonce_too_low_error(
            "server returned an error response: error code -32000: nonce too low"
        ));
        assert!(is_nonce_too_low_error("invalid nonce; got 41, want 42"));
        assert!(!is_nonce_too_low_error("insufficient funds"));
        assert!(!is_nonce_too_low_error("already known"));
        assert!(!is_nonce_too_low_error("replacement transaction underpriced"));
    }

    #[test]
    fn nonce_allocator_allocate_is_monotonic() {
        let alloc = NonceAllocator { next: AtomicU64::new(10), resync_lock: AsyncMutex::new(()) };
        assert_eq!(alloc.allocate(), 10);
        assert_eq!(alloc.allocate(), 11);
        assert_eq!(alloc.allocate(), 12);
        assert_eq!(alloc.peek(), 13);
    }

    #[test]
    fn nonce_allocator_release_of_tail_succeeds() {
        let alloc = NonceAllocator { next: AtomicU64::new(10), resync_lock: AsyncMutex::new(()) };
        let n = alloc.allocate();
        assert_eq!(n, 10);
        alloc.release(n);
        assert_eq!(alloc.peek(), 10, "tail release must rewind");
        assert_eq!(alloc.allocate(), 10);
    }

    #[test]
    fn apply_gas_buffer_is_plus_20pct() {
        assert_eq!(apply_gas_buffer(100_000), 120_000);
        assert_eq!(apply_gas_buffer(86476), 103771);
    }

    #[test]
    fn apply_gas_buffer_saturates() {
        assert_eq!(apply_gas_buffer(u64::MAX), u64::MAX);
    }

    #[test]
    fn nonce_allocator_release_of_non_tail_leaves_gap() {
        let alloc = NonceAllocator { next: AtomicU64::new(10), resync_lock: AsyncMutex::new(()) };
        let n0 = alloc.allocate(); // 10
        let _n1 = alloc.allocate(); // 11
        alloc.release(n0);
        assert_eq!(alloc.peek(), 12, "release of non-tail must not rewind — the gap is accepted");
    }

    #[test]
    fn release_with_outcome_returns_true_on_tail_release() {
        let alloc = NonceAllocator { next: AtomicU64::new(10), resync_lock: AsyncMutex::new(()) };
        let n = alloc.allocate();
        assert!(alloc.release_with_outcome(n), "tail release must succeed");
        assert_eq!(alloc.peek(), 10);
    }

    #[test]
    fn release_with_outcome_returns_false_on_lost_race() {
        let alloc = NonceAllocator { next: AtomicU64::new(10), resync_lock: AsyncMutex::new(()) };
        let n0 = alloc.allocate();
        let _n1 = alloc.allocate();
        assert!(
            !alloc.release_with_outcome(n0),
            "release of non-tail must report failure (leak signal)"
        );
        assert_eq!(alloc.peek(), 12);
    }

    #[test]
    fn rollup_tx_partial_with_nonce_preserves_all_fields() {
        let partial = RollupTxPartial {
            to: Address::from([0x11u8; 20]),
            input: Bytes::from(vec![0xab, 0xcd]),
            gas_limit: 123_456,
            chain_id: 11_155_111,
            batch_index: 42,
            tx_kind: "preconfirm",
        };
        let template = partial.with_nonce(99);
        assert_eq!(template.to, Address::from([0x11u8; 20]));
        assert_eq!(template.input.as_ref(), &[0xab, 0xcd]);
        assert_eq!(template.gas_limit, 123_456);
        assert_eq!(template.chain_id, 11_155_111);
        assert_eq!(template.batch_index, 42);
        assert_eq!(template.tx_kind, "preconfirm");
        assert_eq!(template.nonce, 99);
    }
}
