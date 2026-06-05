//! In-proof DPoS committee read over the witnessed pre-state.
//!
//! Builds one EVM over the block's witnessed pre-state and runs the staking
//! `getEpochCommittee` / `getConsensusKeys` system calls through it, decoding the
//! result into a [`ZkCommittee`] (BLS pubkeys as zkcrypto `G2Affine`). Shared by
//! the SP1 guest and the Nitro enclave so the committee — the trust anchor for
//! [`dpos_cert_verify_zk::verify_finalization`] — is read identically on both.
//!
//! Trust rests on reading the committee from the state the block executes on: a
//! forged committee changes the state root and breaks the L1 hash-chain, so a
//! divergent branch cannot produce a cert that verifies against the committee
//! read here.

use std::{cell::RefCell, sync::Arc};

use alloy_evm::Evm;
use alloy_primitives::{Address, Bytes};
use dpos_cert_verify_zk::{committee_snapshot_zk, CommitteeError, ZkCommittee};
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
/// `epoch` is derived locally from the block number (never from the cert);
/// `staking` is the genesis-frozen predeploy address.
pub fn read_zk_committee(
    input: &EthClientExecutorInput,
    chain_spec: Arc<ChainSpec>,
    epoch: u64,
    staking: Address,
) -> Result<ZkCommittee, CommitteeError> {
    let sealed_headers = input.sealed_headers().collect::<Vec<_>>();
    let trie_db = input
        .witness_db(&sealed_headers)
        .map_err(|e| CommitteeError::Evm(format!("witness_db: {e:?}")))?;
    let header = input.current_block.header.clone();
    let evm_config = FluentEvmConfig::new_with_default_factory(chain_spec);

    // One EVM over the witnessed pre-state, reused across the committee read's
    // calls (`getEpochCommittee` + one `getConsensusKeys` per member). The
    // system-call path commits no state delta, so reuse is sound; the `RefCell`
    // bridges the `StateView::call(&self, …)` shape to `&mut transact_system_call`.
    let evm = RefCell::new(
        evm_config
            .evm_for_block(WrapDatabaseRef(trie_db), &header)
            .map_err(|e| CommitteeError::Evm(format!("evm_for_block: {e:?}")))?,
    );

    let view = |to: Address, calldata: Bytes| -> Result<Bytes, CommitteeError> {
        let out = evm
            .borrow_mut()
            .transact_system_call(Address::ZERO, to, calldata)
            .map_err(|e| CommitteeError::Evm(format!("{e:?}")))?;
        match out.result {
            ExecutionResult::Success { output, .. } => match output {
                Output::Call(b) | Output::Create(b, _) => Ok(b),
            },
            ExecutionResult::Revert { output, .. } => Err(CommitteeError::Evm(format!(
                "revert: {}",
                alloy_primitives::hex::encode(output)
            ))),
            ExecutionResult::Halt { reason, .. } => {
                Err(CommitteeError::Evm(format!("halt: {reason:?}")))
            }
        }
    };

    committee_snapshot_zk(&view, epoch, staking)
}
