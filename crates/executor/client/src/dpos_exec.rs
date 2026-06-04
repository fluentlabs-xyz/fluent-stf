//! DPoS block-execution extension for the STF.
//!
//! The fluentbase node's `FluentBlockExecutor` applies two state-mutating
//! system calls in `apply_pre_execution_changes` on every DPoS-produced block:
//!
//!   * `LivenessSlashing.processBitmap(...)` — from the cert bitmap carried in
//!     `block.header.extra_data` (no-op on empty extra_data / cold start);
//!   * `Staking.commitEpochCommittee(...)` — an ahead-commit catch-up loop that commits the
//!     canonical committee one epoch ahead (PoS spec §4.4).
//!
//! The proving/host STF must replay them byte-for-byte or the re-executed block
//! diverges from the node (`StateRootMismatch`). This module mirrors the node's
//! logic (`crates/node/src/evm.rs`) with only the leaf glue it needs — a minimal
//! `extra_data` decoder and two address constants are vendored so the module
//! pulls no `commonware`/`fluentbase-consensus` deps and stays sp1-buildable.
//!
//! Kept in a separate module per the design note in the node's `evm.rs`.

use alloy_evm::{block::BlockExecutionError, Evm};
use alloy_primitives::{address, Address, Bytes, B256};
use alloy_sol_types::{SolCall, SolError};
use fluentbase_revm::revm::{
    context_interface::{
        result::{ExecutionResult, Output},
        Block as _,
    },
    DatabaseCommit,
};

/// EIP-4788 system sentinel — the `msg.sender` for every predeploy system call
/// (mirrors `fluentbase_types::SYSTEM_ADDRESS`).
const SYSTEM_ADDRESS: Address = address!("0xfffffffffffffffffffffffffffffffffffffffe");
/// `LivenessSlashing` predeploy (mirrors
/// `fluentbase_types::PRECOMPILE_LIVENESS_SLASHING`).
const PRECOMPILE_LIVENESS_SLASHING: Address =
    address!("0x0000000000000000000000000000000000520020");

// Inline ABI — copied verbatim from `crates/node/src/evm.rs` (the node's `sol!`
// is the source of truth). Keep byte-identical or the selectors drift and the
// system calls become unreachable / misclassified.
alloy_sol_types::sol! {
    function processBitmap(
        uint64 epoch,
        uint64 blockNumber,
        uint8 committeeSize,
        bytes calldata signersBitmap
    ) external;

    error EpochCommitteeNotCommitted(uint64 epoch);
    error ValidatorNotFound(address validator);

    function commitEpochCommittee(address[] calldata committee) external;

    struct EpochConsensusKeys {
        bytes blsPubkey;
        bytes32 peerPubkey;
        uint64 activationEpoch;
    }
    function getValidatorsWithKeysAt(uint64 epoch) external view
        returns (address[] memory validators, EpochConsensusKeys[] memory keys);
    function nextEpochToCommit() external view returns (uint64);
    function committeeSelectionEpoch() external view returns (uint64);

    function getEpochBlockInterval() external view returns (uint32);
    function getDposActivationBlock() external view returns (uint64);
}

/// Minimal vendored decode of the canonical attestation wire format
/// (`crates/consensus/src/extra_data.rs`):
/// `[epoch: u64 BE][view: u64 BE][committee_size: u8][bitmap: ceil(N/8) bytes]`.
/// Returns `(epoch, committee_size, bitmap)`; `view` is unused here. Empty input
/// ⇒ `None` (cold start / no previous cert).
fn decode_attestation(buf: &[u8]) -> Result<Option<(u64, u8, Vec<u8>)>, BlockExecutionError> {
    if buf.is_empty() {
        return Ok(None);
    }
    const HDR: usize = 8 + 8 + 1;
    if buf.len() < HDR {
        return Err(BlockExecutionError::msg("liveness decode: extra_data too short"));
    }
    let epoch = u64::from_be_bytes(buf[0..8].try_into().unwrap());
    let committee_size = buf[16];
    if committee_size == 0 {
        return Err(BlockExecutionError::msg("liveness decode: zero committee_size"));
    }
    let expected = HDR + (committee_size as usize).div_ceil(8);
    if buf.len() != expected {
        return Err(BlockExecutionError::msg(format!(
            "liveness decode: length mismatch expected {expected} got {}",
            buf.len()
        )));
    }
    Ok(Some((epoch, committee_size, buf[HDR..].to_vec())))
}

fn encode_process_bitmap_call(
    epoch: u64,
    block_number: u64,
    committee_size: u8,
    bitmap: &[u8],
) -> Vec<u8> {
    processBitmapCall {
        epoch,
        blockNumber: block_number,
        committeeSize: committee_size,
        signersBitmap: Bytes::from(bitmap.to_vec()),
    }
    .abi_encode()
}

/// Execute a `view` system call, returning raw output bytes (fail-loud on
/// revert/halt). View calls don't commit, so the returned `state` is discarded.
fn transact_view<E: Evm>(
    evm: &mut E,
    to: Address,
    calldata: Bytes,
    what: &str,
) -> Result<Bytes, BlockExecutionError> {
    let ras = evm
        .transact_system_call(SYSTEM_ADDRESS, to, calldata)
        .map_err(|e| BlockExecutionError::msg(format!("{what} read failed: {e:?}")))?;
    match ras.result {
        ExecutionResult::Success { output, .. } => Ok(match output {
            Output::Call(b) | Output::Create(b, _) => b,
        }),
        ExecutionResult::Revert { output, .. } => Err(BlockExecutionError::msg(format!(
            "{what} reverted: 0x{}",
            alloy_primitives::hex::encode(output)
        ))),
        ExecutionResult::Halt { reason, .. } => {
            Err(BlockExecutionError::msg(format!("{what} halted: {reason:?}")))
        }
    }
}

fn read_epoch_block_interval<E: Evm>(
    evm: &mut E,
    chain_config_address: Address,
) -> Result<u32, BlockExecutionError> {
    let out = transact_view(
        evm,
        chain_config_address,
        getEpochBlockIntervalCall {}.abi_encode().into(),
        "epoch_block_interval",
    )?;
    getEpochBlockIntervalCall::abi_decode_returns(&out)
        .map_err(|e| BlockExecutionError::msg(format!("epoch_block_interval decode: {e:?}")))
}

fn read_dpos_activation_block<E: Evm>(
    evm: &mut E,
    chain_config_address: Address,
) -> Result<u64, BlockExecutionError> {
    let out = transact_view(
        evm,
        chain_config_address,
        getDposActivationBlockCall {}.abi_encode().into(),
        "dpos_activation_block",
    )?;
    getDposActivationBlockCall::abi_decode_returns(&out)
        .map_err(|e| BlockExecutionError::msg(format!("dpos_activation_block decode: {e:?}")))
}

fn read_next_epoch_to_commit<E: Evm>(
    evm: &mut E,
    staking_address: Address,
) -> Result<u64, BlockExecutionError> {
    let out = transact_view(
        evm,
        staking_address,
        nextEpochToCommitCall {}.abi_encode().into(),
        "nextEpochToCommit",
    )?;
    nextEpochToCommitCall::abi_decode_returns(&out)
        .map_err(|e| BlockExecutionError::msg(format!("nextEpochToCommit decode: {e:?}")))
}

fn read_committee_selection_epoch<E: Evm>(
    evm: &mut E,
    staking_address: Address,
) -> Result<u64, BlockExecutionError> {
    let out = transact_view(
        evm,
        staking_address,
        committeeSelectionEpochCall {}.abi_encode().into(),
        "committeeSelectionEpoch",
    )?;
    committeeSelectionEpochCall::abi_decode_returns(&out)
        .map_err(|e| BlockExecutionError::msg(format!("committeeSelectionEpoch decode: {e:?}")))
}

/// Derive the canonical committee for `epoch`, identical to the on-chain
/// `commitEpochCommittee` verification predicate: read `getValidatorsWithKeysAt`,
/// drop keyless members (`peerPubkey == bytes32(0)`), sort strictly ascending by
/// raw `peerPubkey` bytes (Solidity `bytes32 <` unsigned byte-lex), project to
/// addresses.
fn derive_committee_at<E: Evm>(
    evm: &mut E,
    staking_address: Address,
    epoch: u64,
) -> Result<Vec<Address>, BlockExecutionError> {
    let out = transact_view(
        evm,
        staking_address,
        getValidatorsWithKeysAtCall { epoch }.abi_encode().into(),
        "getValidatorsWithKeysAt",
    )?;
    let ret = getValidatorsWithKeysAtCall::abi_decode_returns(&out)
        .map_err(|e| BlockExecutionError::msg(format!("getValidatorsWithKeysAt decode: {e:?}")))?;
    let mut keyed: Vec<(Address, B256)> = ret
        .validators
        .into_iter()
        .zip(ret.keys)
        .filter(|(_, k)| k.peerPubkey != B256::ZERO)
        .map(|(addr, k)| (addr, k.peerPubkey))
        .collect();
    keyed.sort_unstable_by(|(_, a), (_, b)| a.as_slice().cmp(b.as_slice()));
    Ok(keyed.into_iter().map(|(addr, _)| addr).collect())
}

/// Replay the node's DPoS pre-execution system calls onto `evm` (already at the
/// post-`apply_pre_execution_changes` state). No-op when DPoS is not configured
/// (`staking`/`chain_config` zero) or for pre-activation blocks (Tempo-era blocks
/// were produced without these calls — gating on the activation block is the
/// STF's stand-in for the node's "staking configured" runtime flag). The
/// activation block itself IS the first DPoS block, so it is replayed — matching
/// the node (no block-number gate), the host witness, and the enclave verify
/// (both `>= activation`).
pub(crate) fn apply_dpos_pre_execution<E>(
    evm: &mut E,
    extra_data: &[u8],
    staking_address: Address,
    chain_config_address: Address,
) -> Result<(), BlockExecutionError>
where
    E: Evm,
    E::DB: DatabaseCommit,
{
    if staking_address.is_zero() || chain_config_address.is_zero() {
        return Ok(());
    }
    let block_number: u64 = evm.block().number().saturating_to();
    if block_number < fluent_stf_primitives::DPOS_ACTIVATION_BLOCK {
        return Ok(());
    }

    // ── processBitmap (from extra_data) ──────────────────────────────────────
    if let Some((epoch, committee_size, bitmap)) = decode_attestation(extra_data)? {
        let calldata = encode_process_bitmap_call(epoch, block_number, committee_size, &bitmap);
        let ras = evm
            .transact_system_call(SYSTEM_ADDRESS, PRECOMPILE_LIVENESS_SLASHING, calldata.into())
            .map_err(|e| BlockExecutionError::msg(format!("liveness sys call: {e:?}")))?;
        // A Solidity revert lands inside `Ok(ras)` with non-Success result and
        // rolled-back state. The transient slash sub-path selectors
        // (committee-not-yet-committed / victim-removed) are tolerated; every
        // other revert/halt is a deterministic caller bug → fail the block.
        match ras.result {
            ExecutionResult::Success { .. } => evm.db_mut().commit(ras.state),
            ExecutionResult::Revert { output, .. } => {
                let sel = output.get(..4);
                if sel == Some(EpochCommitteeNotCommitted::SELECTOR.as_slice()) ||
                    sel == Some(ValidatorNotFound::SELECTOR.as_slice())
                {
                    // transient slash sub-path — skip this block's liveness accounting
                } else {
                    return Err(BlockExecutionError::msg(format!(
                        "processBitmap reverted (caller bug, selector {sel:?}): 0x{}",
                        alloy_primitives::hex::encode(&output)
                    )));
                }
            }
            ExecutionResult::Halt { reason, .. } => {
                return Err(BlockExecutionError::msg(format!("processBitmap halted: {reason:?}")))
            }
        }
    }

    // ── commitEpochCommittee ahead-commit catch-up (PoS spec §4.4) ──────────
    let interval = read_epoch_block_interval(evm, chain_config_address)?;
    let activation = read_dpos_activation_block(evm, chain_config_address)?;
    let current_epoch = fluent_stf_primitives::epoch_of_block(block_number, interval, activation);
    loop {
        let next = read_next_epoch_to_commit(evm, staking_address)?;
        if next > current_epoch + 1 {
            break; // nothing more committable within the lookahead horizon
        }
        let sel = read_committee_selection_epoch(evm, staking_address)?;
        let committee = derive_committee_at(evm, staking_address, sel)?;
        let calldata = commitEpochCommitteeCall { committee }.abi_encode();
        // FAIL-LOUD: the commit is liveness-critical and derives from
        // deterministic state, so a revert/halt is a real bug. A revert lands in
        // `Ok(ras)` with a non-Success result whose commit is a no-op that never
        // advances the cursor (infinite loop), so check the result explicitly.
        let ras =
            evm.transact_system_call(SYSTEM_ADDRESS, staking_address, calldata.into()).map_err(
                |e| BlockExecutionError::msg(format!("commitEpochCommittee sys call: {e:?}")),
            )?;
        match ras.result {
            ExecutionResult::Success { .. } => evm.db_mut().commit(ras.state),
            ExecutionResult::Revert { output, .. } => {
                return Err(BlockExecutionError::msg(format!(
                    "commitEpochCommittee reverted (epoch {next}): 0x{}",
                    alloy_primitives::hex::encode(output)
                )))
            }
            ExecutionResult::Halt { reason, .. } => {
                return Err(BlockExecutionError::msg(format!(
                    "commitEpochCommittee halted (epoch {next}): {reason:?}"
                )))
            }
        }
    }

    Ok(())
}
