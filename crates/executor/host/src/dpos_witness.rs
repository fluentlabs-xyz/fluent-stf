//! DPoS committee witness coverage (task `dpos_l1_rollup_committee_binding`,
//! Phase 4).
//!
//! The witness the host produces for a block covers only the storage slots
//! READ while executing that block. A normal block never touches the staking
//! committee storage, so the enclave's identical committee read over the
//! witness would otherwise fail-loud on a missing slot. Running the SAME read
//! here — through the recording witness DB (`ExExDb` / `BasicRpcDb`), before the
//! witness is materialised — records exactly those slots so the witness covers
//! them.
//!
//! Errors are logged, not fatal: the enclave makes the real accept/reject
//! decision, and the slots accessed before any error are still recorded (the
//! enclave hits the same error at the same point).

use std::cell::RefCell;

use alloy_primitives::{Address, Bytes};
use reth_evm::{ConfigureEvm, Evm};
use reth_primitives_traits::NodePrimitives;
use revm::{
    context_interface::result::{ExecutionResult, Output},
    database::CacheDB,
    DatabaseRef,
};

/// Force the committee + consensus-keys slots for `block_number`'s epoch into
/// the witness by reading them through `db` (the recording witness DB). No-op
/// before DPoS activation. `db` is the same DB the caller will materialise the
/// witness from, so reads here are captured there.
pub(crate) fn cover_committee_witness<C, D>(
    evm_config: &C,
    db: D,
    header: &<C::Primitives as NodePrimitives>::BlockHeader,
    block_number: u64,
) where
    C: ConfigureEvm,
    D: DatabaseRef + std::fmt::Debug,
{
    if block_number < fluent_stf_primitives::DPOS_ACTIVATION_BLOCK {
        return;
    }

    let epoch = fluent_stf_primitives::epoch_of_block(
        block_number,
        fluent_stf_primitives::EPOCH_BLOCK_INTERVAL,
        fluent_stf_primitives::DPOS_ACTIVATION_BLOCK,
    );
    let staking = fluent_stf_primitives::DPOS_STAKING_ADDRESS;

    // One EVM over the recording DB, reused across the read's calls
    // (`getEpochCommittee` + one `getConsensusKeys` per member). The system-call
    // path does not commit its state delta, so reuse is sound; the `RefCell`
    // bridges `StateView::call(&self, …)` to the `&mut` `transact_system_call`.
    let evm = match evm_config.evm_for_block(CacheDB::new(db), header) {
        Ok(evm) => RefCell::new(evm),
        Err(e) => {
            tracing::warn!(block_number, "dpos witness: evm_for_block failed: {e:?}");
            return;
        }
    };

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

    if let Err(e) = dpos_cert_verify::epoch_committee_snapshot(&view, block_number, epoch, staking)
    {
        tracing::warn!(
            block_number,
            epoch,
            "dpos witness: committee read errored (slots recorded up to the error; the enclave \
             makes the real decision): {e}"
        );
    }
}
