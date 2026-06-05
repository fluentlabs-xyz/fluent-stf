//! Vendored DPoS committee cert-verify glue (Phase 1, copy-now).
//!
//! Phase 6 replaces this crate with a git-pin dep on
//! `fluentbase/crates/dpos-cert-verify`. The thin fluentbase glue is copied
//! here; the heavy cert/scheme types come from `commonware-*` pinned to the
//! SAME revision as fluentbase (`v2026.4.0`) so the core cannot drift.
//!
//! Entry point: [`verify_block_committee_cert`] — for a just-executed block,
//! reads the epoch committee from the witnessed pre-state (via a caller-supplied
//! [`StateView`]) and verifies the block's Simplex finalization certificate. A
//! failed/absent cert ⇒ the caller (the Nitro enclave) refuses to attest.

use alloy_primitives::{Address, B256};
use commonware_codec::Decode as _;
use commonware_consensus::simplex::{scheme::bls12381_multisig, types::Finalization};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, certificate::Scheme as _, ed25519,
};
use rand_core::CryptoRngCore;

mod digest;
mod scheme;
mod staking;

pub use digest::Digest;
pub use scheme::{epoch_committee_from_snapshot, EpochCommittee};
pub use staking::{
    epoch_committee_snapshot, epoch_of_block, ConsensusKeys, StateView, ValidatorSetSnapshot,
    ValidatorWithKeys,
};

/// BLS variant fixed to MinSig (mirrors `fluentbase_bls::Variant`).
pub type Variant = MinSig;
/// Identity (peer) public key — participant ordering key.
pub type PeerPubkey = ed25519::PublicKey;
/// BLS public key (G2 compressed, 96 B for MinSig).
pub type BlsPubkey =
    <MinSig as commonware_cryptography::bls12381::primitives::variant::Variant>::Public;
/// Macro-generated multisig verifier scheme.
pub type Scheme = bls12381_multisig::Scheme<PeerPubkey, Variant>;
/// The finalization certificate type the enclave verifies.
pub type Cert = Finalization<Scheme, Digest>;

/// Genesis-frozen epoch geometry + chain identity. Hardcoded per-network in the
/// enclave (P2 decision) — NOT read per-block from `ChainConfig`.
#[derive(Clone, Copy, Debug)]
pub struct Geometry {
    pub activation: u64,
    pub interval: u32,
    pub chain_id: u64,
    pub staking_address: Address,
}

/// Failure modes of the committee read + cert verify. Every variant means the
/// caller MUST refuse to attest the block.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("EVM view failed: {0}")]
    Evm(String),
    #[error("staking call reverted: {0}")]
    CallReverted(String),
    #[error("ABI decode: {0}")]
    AbiDecode(String),
    #[error("BLS key decode: {0}")]
    BlsKey(String),
    #[error("peer key decode")]
    PeerKey,
    #[error("committee member {0} has no consensus keys")]
    CommitteeMemberKeyless(Address),
    #[error("committee BiMap construction: {0}")]
    Committee(commonware_utils::ordered::Error),
    #[error("cert digest != executed block_hash")]
    DigestMismatch,
    #[error("cert decode: {0}")]
    CertDecode(String),
    #[error("cert verification failed (quorum/signature)")]
    CertInvalid,
}

/// Decode the commonware-codec-encoded finalization cert (the bytes the node's
/// `consensus_getFinalization` RPC ships as hex), bounding the signer bitmap to
/// `max_signers`. The cert is attacker-controlled — it reaches the enclave from
/// the untrusted host — so the bound is load-bearing: the unbounded config caps
/// the bitmap at `u32::MAX` bits, letting a ~10-byte input whose length prefix
/// claims ~`u32::MAX` signers force a ~512 MB `VecDeque::with_capacity` before any
/// chunk byte is read (an alloc-failure abort the enclave's `catch_unwind` cannot
/// contain). Callers pass the epoch committee's participant count, so a cert
/// claiming more signers than the committee is rejected before allocating.
pub fn decode_finalization(bytes: &[u8], max_signers: usize) -> Result<Cert, Error> {
    Cert::decode_cfg(bytes, &max_signers).map_err(|e| Error::CertDecode(format!("{e:?}")))
}

/// The commonware `Finalization` decomposed into the raw fields the blst-free
/// verify-core (`dpos-cert-verify-zk`) consumes. Produced host-side by the proxy
/// so commonware/blst never enters the guest or enclave. NOT a trust point — the
/// guest/enclave re-derive the committee and re-run the pairing over these bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawCertParts {
    /// Aggregate signature, compressed G1 (MinSig).
    pub sig_g1: [u8; 48],
    /// Signer bitmap, LSB-first, `ceil(n/8)` bytes where `n` = participant count.
    pub bitmap: Vec<u8>,
    pub round_epoch: u64,
    pub round_view: u64,
    pub parent_view: u64,
}

/// Decode a commonware finalization cert and extract [`RawCertParts`]. The
/// signer bitmap is rebuilt LSB-first from the decoded participant indices; the
/// aggregate signature is the cert's trailing 48-byte compressed G1 (the fixed
/// MinSig layout — guaranteed once the decode above succeeds).
pub fn transcode_finalization(bytes: &[u8], max_signers: usize) -> Result<RawCertParts, Error> {
    let cert = decode_finalization(bytes, max_signers)?;
    let n = cert.certificate.signers.len();
    let mut bitmap = vec![0u8; n.div_ceil(8)];
    for participant in cert.certificate.signers.iter() {
        let i = usize::from(participant);
        bitmap[i / 8] |= 1 << (i % 8);
    }
    let sig_g1: [u8; 48] = bytes
        .get(bytes.len().wrapping_sub(48)..)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| Error::CertDecode("cert shorter than a 48-byte G1 signature".into()))?;
    Ok(RawCertParts {
        sig_g1,
        bitmap,
        round_epoch: cert.proposal.round.epoch().get(),
        round_view: cert.proposal.round.view().get(),
        parent_view: cert.proposal.parent.get(),
    })
}

/// Fluent's base BLS namespace (vendored verbatim from
/// `fluentbase/crates/bls/src/namespace.rs` — a consensus-critical drift-guard:
/// the enclave MUST sign under the same namespace the Engine does). Layout:
/// `b"FLUENT_DPOS_V1_" || chain_id.to_be_bytes()` = 23 bytes; commonware appends
/// the per-subject suffix (`_FINALIZE`, …) internally. `chain_id` prevents
/// cross-chain replay.
fn fluent_namespace(chain_id: u64) -> Vec<u8> {
    let mut ns = Vec::with_capacity(15 + 8);
    ns.extend_from_slice(b"FLUENT_DPOS_V1_");
    ns.extend_from_slice(&chain_id.to_be_bytes());
    ns
}

/// Verify that the just-executed `block_hash` is finalized by the epoch
/// committee read (via `view`) from the witnessed pre-state. `Ok(())` ⇒ the
/// block carries a valid 2f+1 committee finalization; any `Err` ⇒ refuse to
/// attest.
///
/// Trust rests on step 2: the committee is read from the state the block
/// executes on, so a forged committee changes the state root and breaks the L1
/// hash-chain. `rng` is local verification randomness (need NOT match the
/// Engine); `epoch` is derived independently from hardcoded geometry, never the
/// cert.
pub fn verify_block_committee_cert<R>(
    view: &impl StateView,
    geom: &Geometry,
    block_number: u64,
    block_hash: B256,
    cert_bytes: &[u8],
    rng: &mut R,
) -> Result<(), Error>
where
    R: CryptoRngCore,
{
    let epoch = epoch_of_block(block_number, geom.interval, geom.activation);
    let snap = epoch_committee_snapshot(view, block_number, epoch, geom.staking_address)?;
    verify_cert_with_snapshot(&snap, geom.chain_id, block_hash, cert_bytes, rng)
}

/// The post-execute half of [`verify_block_committee_cert`]. The enclave reads
/// `snap` (via [`epoch_committee_snapshot`]) BEFORE `execute` consumes the
/// witnessed state, then calls this with the executed `block_hash`. Splitting
/// the two resolves the borrow/move: `snap` is owned (no live borrow on the db).
pub fn verify_cert_with_snapshot<R>(
    snap: &ValidatorSetSnapshot,
    chain_id: u64,
    block_hash: B256,
    cert_bytes: &[u8],
    rng: &mut R,
) -> Result<(), Error>
where
    R: CryptoRngCore,
{
    // 1. Build the verifier scheme from the (state-anchored) committee snapshot.
    let committee = epoch_committee_from_snapshot(snap).map_err(Error::Committee)?;
    let scheme = Scheme::verifier(&fluent_namespace(chain_id), committee.bimap);
    // 2. Decode the cert bounded to THIS committee's participant count, so an attacker-supplied
    //    cert claiming more signers is rejected before it allocates the signer bitmap (see
    //    `decode_finalization`).
    let cert = decode_finalization(cert_bytes, scheme.certificate_codec_config())?;
    // 3. Bind the cert to THIS executed block — Proposal.payload IS the digest.
    if cert.proposal.payload != Digest(block_hash) {
        return Err(Error::DigestMismatch);
    }
    // 4. Verify the 2f+1 multisig.
    if !cert.verify(rng, &scheme, &commonware_parallel::Sequential) {
        return Err(Error::CertInvalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_finalization_rejects_garbage() {
        // A signed-cert happy-path fixture is deferred (needs a fluentbase
        // emitter); this covers the decode error path the enclave hits on a
        // malformed cert.
        assert!(matches!(
            decode_finalization(&[0xde, 0xad, 0xbe, 0xef], 256),
            Err(Error::CertDecode(_))
        ));
        assert!(matches!(decode_finalization(&[], 256), Err(Error::CertDecode(_))));
    }

    #[test]
    fn fluent_namespace_layout_is_stable() {
        let ns = fluent_namespace(20994);
        assert_eq!(ns.len(), 23);
        assert_eq!(&ns[..15], b"FLUENT_DPOS_V1_");
        assert_eq!(&ns[15..], &20994u64.to_be_bytes());
    }

    #[test]
    fn fluent_namespace_distinguishes_chain_ids() {
        assert_ne!(fluent_namespace(1), fluent_namespace(2));
    }
}
