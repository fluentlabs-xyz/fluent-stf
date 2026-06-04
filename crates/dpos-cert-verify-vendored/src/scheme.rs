//! Per-epoch committee snapshot → typed [`EpochCommittee`]. VENDORED from
//! `fluentbase/crates/bls/src/scheme.rs` (`EpochCommittee`)
//! + `fluentbase/crates/consensus/src/scheme.rs` (`epoch_committee_from_snapshot`).
//!
//! commonware sorts the participant set by lex byte order of `PeerPubkey`; the
//! resulting `Participant` index in every `Certificate` equals the validator's
//! position in this sorted list. The committee snapshot is fed in **contract
//! order, verbatim** — commonware re-sorts internally on `BiMap` construction.

use commonware_utils::{ordered::BiMap, TryCollect};

use crate::{staking::ValidatorSetSnapshot, BlsPubkey, PeerPubkey};

/// Per-epoch consensus committee: an epoch identifier paired with the
/// commonware-sorted `BiMap<PeerPubkey, BlsPubkey>`.
#[derive(Clone, Debug)]
pub struct EpochCommittee {
    pub epoch: u64,
    pub bimap: BiMap<PeerPubkey, BlsPubkey>,
}

impl EpochCommittee {
    /// Trusted constructor: caller guarantees the pubkeys passed PoP on-chain.
    pub fn from_pairs<I>(epoch: u64, pairs: I) -> Result<Self, commonware_utils::ordered::Error>
    where
        I: IntoIterator<Item = (PeerPubkey, BlsPubkey)>,
    {
        let bimap: BiMap<PeerPubkey, BlsPubkey> = pairs.into_iter().try_collect()?;
        Ok(Self { epoch, bimap })
    }
}

/// Build the typed [`EpochCommittee`] from one epoch's committee snapshot.
pub fn epoch_committee_from_snapshot(
    snap: &ValidatorSetSnapshot,
) -> Result<EpochCommittee, commonware_utils::ordered::Error> {
    EpochCommittee::from_pairs(
        snap.epoch,
        snap.validators.iter().map(|v| (v.keys.peer_pubkey.clone(), v.keys.bls_pubkey)),
    )
}
