//! Staking committee read. VENDORED from
//! `fluentbase/crates/staking-reader/src/reader.rs` — ABI + decode copied
//! verbatim. The EVM plumbing is NOT here: callers pass a `view` closure
//! `(to, calldata) -> Result<Bytes, Error>` that runs a system-call against the
//! witnessed pre-state. This keeps the leaf crate free of reth/revm and lets
//! the enclave AND the host orchestrator share one read path.

use alloy_primitives::{Address, Bytes, B256};
use alloy_sol_types::SolCall;
use commonware_codec::DecodeExt as _;

use crate::{BlsPubkey, Error, PeerPubkey};

/// Compressed BLS pubkey byte length (G2, MinSig).
const PUBKEY_BYTES: usize = 96;

/// Solidity ABI subset, VENDORED verbatim from the staking-reader.
mod abi {
    use alloy_sol_types::sol;

    sol! {
        #[derive(Debug)]
        struct ConsensusKeys {
            bytes blsPubkey;
            bytes32 peerPubkey;
            uint64 activationEpoch;
        }

        function getConsensusKeys(address validator)
            external view returns (ConsensusKeys);
        function getEpochCommittee(uint64 epoch) external view returns (address[]);
    }
}

/// A read-only system call against the witnessed pre-state: `(to, calldata) ->
/// return bytes`. The enclave/host build this over their `FluentEvmConfig` +
/// witnessed db.
pub trait StateView {
    fn call(&self, to: Address, calldata: Bytes) -> Result<Bytes, Error>;
}

impl<F> StateView for F
where
    F: Fn(Address, Bytes) -> Result<Bytes, Error>,
{
    fn call(&self, to: Address, calldata: Bytes) -> Result<Bytes, Error> {
        (self)(to, calldata)
    }
}

/// A validator's consensus identity, decoded and validated. Order in any `Vec`
/// is **contract order, verbatim** — never sorted here.
#[derive(Clone, Debug)]
pub struct ConsensusKeys {
    pub bls_pubkey: BlsPubkey,
    pub peer_pubkey: PeerPubkey,
    pub activation_epoch: u64,
}

/// A validator address paired with its consensus keys.
#[derive(Clone, Debug)]
pub struct ValidatorWithKeys {
    pub address: Address,
    pub keys: ConsensusKeys,
}

/// Validator set as read at one specific (pre-)state. `epoch` is computed
/// locally via [`epoch_of_block`], never via an `eth_call`.
#[derive(Clone, Debug)]
pub struct ValidatorSetSnapshot {
    pub block_hash: B256,
    pub block_number: u64,
    pub epoch: u64,
    pub validators: Vec<ValidatorWithKeys>,
}

/// Relative DPoS epoch: `(block_number - dpos_activation_block) / interval`.
/// VENDORED verbatim — equals the Engine's `OriginEpocher::containing` for
/// `block_number >= dpos_activation_block` (the gated range). `saturating_sub`
/// mirrors the contract's `block.number < activation ⇒ 0` clamp.
#[inline]
pub fn epoch_of_block(
    block_number: u64,
    epoch_block_interval: u32,
    dpos_activation_block: u64,
) -> u64 {
    block_number.saturating_sub(dpos_activation_block) / epoch_block_interval as u64
}

/// VENDORED verbatim: decode one ABI `ConsensusKeys` tuple. Keys go through the
/// subgroup-checked commonware decoders, so a malformed blob is rejected here.
fn decode_consensus_keys(k: abi::ConsensusKeys) -> Result<ConsensusKeys, Error> {
    if k.blsPubkey.len() != PUBKEY_BYTES {
        return Err(Error::AbiDecode(format!(
            "blsPubkey length {} != {PUBKEY_BYTES}",
            k.blsPubkey.len()
        )));
    }
    let bls_pubkey =
        BlsPubkey::decode(k.blsPubkey.as_ref()).map_err(|e| Error::BlsKey(format!("{e:?}")))?;
    let peer_pubkey = PeerPubkey::decode(k.peerPubkey.as_slice()).map_err(|_| Error::PeerKey)?;
    Ok(ConsensusKeys { bls_pubkey, peer_pubkey, activation_epoch: k.activationEpoch })
}

#[inline]
fn is_unset(k: &abi::ConsensusKeys) -> bool {
    k.blsPubkey.is_empty()
}

fn epoch_committee(
    view: &impl StateView,
    epoch: u64,
    staking: Address,
) -> Result<Vec<Address>, Error> {
    let cd = abi::getEpochCommitteeCall { epoch }.abi_encode().into();
    let ret = view.call(staking, cd)?;
    abi::getEpochCommitteeCall::abi_decode_returns(&ret)
        .map_err(|e| Error::AbiDecode(e.to_string()))
}

fn consensus_keys(
    view: &impl StateView,
    validator: Address,
    staking: Address,
) -> Result<Option<ConsensusKeys>, Error> {
    let cd = abi::getConsensusKeysCall { validator }.abi_encode().into();
    let ret = view.call(staking, cd)?;
    let k = abi::getConsensusKeysCall::abi_decode_returns(&ret)
        .map_err(|e| Error::AbiDecode(e.to_string()))?;
    if is_unset(&k) {
        return Ok(None);
    }
    Ok(Some(decode_consensus_keys(k)?))
}

/// Frozen committee for `epoch` + full consensus keys, read via `view` against
/// the witnessed pre-state. A keyless committee member is a typed error, never
/// silently skipped.
pub fn epoch_committee_snapshot(
    view: &impl StateView,
    block_number: u64,
    epoch: u64,
    staking: Address,
) -> Result<ValidatorSetSnapshot, Error> {
    let committee = epoch_committee(view, epoch, staking)?;
    let validators = committee
        .into_iter()
        .map(|address| {
            let keys = consensus_keys(view, address, staking)?
                .ok_or(Error::CommitteeMemberKeyless(address))?;
            Ok(ValidatorWithKeys { address, keys })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    Ok(ValidatorSetSnapshot { block_hash: B256::ZERO, block_number, epoch, validators })
}

#[cfg(test)]
mod tests {
    use super::epoch_of_block;

    #[test]
    fn epoch_relative_to_activation() {
        // activation=64, interval=32: anchor is relative epoch 0; +1 every 32.
        assert_eq!(epoch_of_block(64, 32, 64), 0);
        assert_eq!(epoch_of_block(95, 32, 64), 0);
        assert_eq!(epoch_of_block(96, 32, 64), 1);
        assert_eq!(epoch_of_block(162, 32, 64), 3);
        // pre-activation clamps to epoch 0 (saturating_sub).
        assert_eq!(epoch_of_block(30, 32, 64), 0);
    }
}
