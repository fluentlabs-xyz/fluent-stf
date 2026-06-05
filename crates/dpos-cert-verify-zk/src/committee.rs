//! Committee read from witnessed pre-state, mirroring the vendored
//! `dpos-cert-verify::staking` ABI but decoding the on-chain 96-B `blsPubkey`
//! into a subgroup-checked zkcrypto `G2Affine` (instead of commonware/blst).
//!
//! The caller supplies a `view` closure that runs a `getEpochCommittee` /
//! `getConsensusKeys` system call against the block's pre-state; the resulting
//! committee is the in-proof trust anchor for [`super::verify_finalization`].

use alloc::{format, string::String, vec::Vec};

use alloy_primitives::{Address, Bytes};
use alloy_sol_types::SolCall;
use bls12_381::G2Affine;

use crate::{ZkCommittee, ZkValidator, BLS_PUBKEY_LEN};

/// Solidity ABI subset, identical to the vendored staking-reader.
mod abi {
    use alloy_sol_types::sol;

    sol! {
        struct ConsensusKeys {
            bytes blsPubkey;
            bytes32 peerPubkey;
            uint64 activationEpoch;
        }

        function getConsensusKeys(address validator) external view returns (ConsensusKeys);
        function getEpochCommittee(uint64 epoch) external view returns (address[]);
    }
}

/// A read-only system call against the witnessed pre-state.
pub trait StateView {
    fn call(&self, to: Address, calldata: Bytes) -> Result<Bytes, CommitteeError>;
}

impl<F> StateView for F
where
    F: Fn(Address, Bytes) -> Result<Bytes, CommitteeError>,
{
    fn call(&self, to: Address, calldata: Bytes) -> Result<Bytes, CommitteeError> {
        (self)(to, calldata)
    }
}

/// Failure of the committee read. Any variant ⇒ no committee ⇒ refuse to attest.
#[derive(Debug)]
pub enum CommitteeError {
    Evm(String),
    AbiDecode(String),
    /// `blsPubkey` is not a valid compressed G2 point (subgroup/encoding).
    BadBlsKey(String),
    /// A committee member has no consensus keys registered.
    KeylessMember(Address),
}

fn epoch_committee(
    view: &impl StateView,
    epoch: u64,
    staking: Address,
) -> Result<Vec<Address>, CommitteeError> {
    let cd = abi::getEpochCommitteeCall { epoch }.abi_encode().into();
    let ret = view.call(staking, cd)?;
    abi::getEpochCommitteeCall::abi_decode_returns(&ret)
        .map_err(|e| CommitteeError::AbiDecode(format!("{e}")))
}

fn consensus_keys(
    view: &impl StateView,
    validator: Address,
    staking: Address,
) -> Result<Option<ZkValidator>, CommitteeError> {
    let cd = abi::getConsensusKeysCall { validator }.abi_encode().into();
    let ret = view.call(staking, cd)?;
    let k = abi::getConsensusKeysCall::abi_decode_returns(&ret)
        .map_err(|e| CommitteeError::AbiDecode(format!("{e}")))?;
    if k.blsPubkey.is_empty() {
        return Ok(None);
    }
    if k.blsPubkey.len() != BLS_PUBKEY_LEN {
        return Err(CommitteeError::BadBlsKey(format!(
            "blsPubkey length {} != {BLS_PUBKEY_LEN}",
            k.blsPubkey.len()
        )));
    }
    let mut bls_bytes = [0u8; BLS_PUBKEY_LEN];
    bls_bytes.copy_from_slice(&k.blsPubkey);
    let bls_g2: G2Affine = Option::from(G2Affine::from_compressed(&bls_bytes))
        .ok_or_else(|| CommitteeError::BadBlsKey("not a valid G2 point".into()))?;
    Ok(Some(ZkValidator { peer: k.peerPubkey.0, bls_g2 }))
}

/// Read the frozen committee for `epoch` from the pre-state via `view`. Returns
/// it in commonware-sorted order (ascending peer key), ready for
/// [`super::verify_finalization`]. A keyless member is an error, never skipped.
pub fn committee_snapshot_zk(
    view: &impl StateView,
    epoch: u64,
    staking: Address,
) -> Result<ZkCommittee, CommitteeError> {
    let addresses = epoch_committee(view, epoch, staking)?;
    let mut validators = Vec::with_capacity(addresses.len());
    for address in addresses {
        let v = consensus_keys(view, address, staking)?
            .ok_or(CommitteeError::KeylessMember(address))?;
        validators.push(v);
    }
    Ok(ZkCommittee::new_sorted(epoch, validators))
}
