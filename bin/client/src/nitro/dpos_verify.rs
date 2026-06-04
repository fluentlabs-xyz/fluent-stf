//! In-enclave DPoS committee certificate verification (task
//! `dpos_l1_rollup_committee_binding`, Phase 2).
//!
//! Before signing an execution preconfirmation the enclave reads the epoch
//! committee from the *witnessed pre-state* (the state the block executes on)
//! and verifies the block's Simplex finalization certificate against it. A
//! forged committee changes the state root and breaks the L1 hash-chain, so a
//! divergent branch cannot produce a cert that verifies here ⇒ it is never
//! preconfirmed ⇒ the batch goes corrupted past `preconfirmWindow`.
//!
//! Split into a pre-execute read (returns an owned snapshot, releasing the
//! witness-db borrow so `execute` can consume `input`) and a post-execute
//! verify against the executed block hash.

use std::{cell::RefCell, sync::Arc};

use alloy_evm::Evm;
use alloy_primitives::{Address, Bytes, B256};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use reth_chainspec::ChainSpec;
use reth_evm::ConfigureEvm;
use revm::{
    context_interface::result::{ExecutionResult, Output},
    database::WrapDatabaseRef,
};
use rsp_client_executor::{
    evm::FluentEvmConfig,
    io::{EthClientExecutorInput, WitnessInput},
};

/// Read the epoch committee for `input`'s block from its witnessed pre-state.
///
/// `Ok(None)` ⇒ no committee verification is required for this block: either it
/// precedes the hardcoded DPoS activation, or no certificate was supplied
/// (Phase 3 wires real certs; until then the enclave keeps the existing
/// no-verify preconf path).
pub(crate) fn read_committee_snapshot(
    input: &EthClientExecutorInput,
    cert: &[u8],
    chain_spec: Arc<ChainSpec>,
) -> anyhow::Result<Option<dpos_cert_verify::ValidatorSetSnapshot>> {
    let block_number = input.current_block.header.number;
    // Genesis-frozen, per-network constants from `fluent-stf-primitives` — the
    // same source the host orchestrator's committee-read reads, so the two sites
    // cannot drift.
    if block_number < fluent_stf_primitives::DPOS_ACTIVATION_BLOCK || cert.is_empty() {
        return Ok(None);
    }

    let epoch = fluent_stf_primitives::epoch_of_block(
        block_number,
        fluent_stf_primitives::EPOCH_BLOCK_INTERVAL,
        fluent_stf_primitives::DPOS_ACTIVATION_BLOCK,
    );

    let sealed_headers = input.sealed_headers().collect::<Vec<_>>();
    let trie_db =
        input.witness_db(&sealed_headers).map_err(|e| anyhow::anyhow!("witness_db: {e:?}"))?;
    let header = input.current_block.header.clone();
    let evm_config = FluentEvmConfig::new_with_default_factory(chain_spec);

    // One EVM over the witnessed pre-state, reused across the committee read's
    // calls (`getEpochCommittee` + one `getConsensusKeys` per member). The
    // system-call path does not commit its state delta, so reuse is sound; the
    // `RefCell` bridges the `StateView::call(&self, …)` shape to the `&mut`
    // `transact_system_call` (revm has no blanket `DatabaseRef for &T`).
    let evm = RefCell::new(
        evm_config
            .evm_for_block(WrapDatabaseRef(trie_db), &header)
            .map_err(|e| anyhow::anyhow!("evm_for_block: {e:?}"))?,
    );

    let view = |to: Address, calldata: Bytes| -> Result<Bytes, dpos_cert_verify::Error> {
        let out = evm
            .borrow_mut()
            .transact_system_call(Address::ZERO, to, calldata)
            .map_err(|e| dpos_cert_verify::Error::Evm(format!("{e:?}")))?;
        match out.result {
            ExecutionResult::Success { output, .. } => match output {
                Output::Call(b) | Output::Create(b, _) => Ok(b),
            },
            ExecutionResult::Revert { output, .. } => {
                Err(dpos_cert_verify::Error::CallReverted(alloy_primitives::hex::encode(output)))
            }
            ExecutionResult::Halt { reason, .. } => {
                Err(dpos_cert_verify::Error::CallReverted(format!("halt: {reason:?}")))
            }
        }
    };

    let snap = dpos_cert_verify::epoch_committee_snapshot(
        &view,
        block_number,
        epoch,
        fluent_stf_primitives::DPOS_STAKING_ADDRESS,
    )
    .map_err(|e| anyhow::anyhow!("committee read: {e}"))?;
    Ok(Some(snap))
}

/// Verify the executed `block_hash` is finalized by the snapshot committee.
/// Any `Err` means the enclave must refuse to attest. `nsm_entropy` seeds the
/// local batch-verification RNG (need not match the Engine — it only randomises
/// the multi-scalar batching, not the accept/reject outcome).
pub(crate) fn verify_executed(
    snap: &dpos_cert_verify::ValidatorSetSnapshot,
    block_hash: B256,
    cert: &[u8],
    nsm_entropy: &[u8],
) -> anyhow::Result<()> {
    let mut seed = [0u8; 32];
    let n = nsm_entropy.len().min(32);
    seed[..n].copy_from_slice(&nsm_entropy[..n]);
    let mut rng = ChaCha20Rng::from_seed(seed);

    dpos_cert_verify::verify_cert_with_snapshot(
        snap,
        fluent_stf_primitives::FLUENT_CHAIN_ID,
        block_hash,
        cert,
        &mut rng,
    )
    .map_err(|e| anyhow::anyhow!("committee cert verify failed: {e}"))
}
