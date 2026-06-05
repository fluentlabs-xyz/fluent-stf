//! Blst-free DPoS finalization-certificate verify-core (zkcrypto `bls12_381`).
//!
//! Runs identically in the SP1 guest (precompile-accelerated) and the Nitro
//! enclave. The committee is read in-proof from witnessed pre-state; the pairing
//! executes in the zkVM. A divergent branch changes the state root, so it cannot
//! read a committee that finalized the canonical block ⇒ its cert never verifies.
//!
//! ## Signed-message layout (pinned byte-for-byte against commonware
//! `v2026.4.0` AND a real devnet cert, `tests/equiv.rs`)
//!
//! ```text
//! base_ns      = b"FLUENT_DPOS_V1_" ‖ chain_id.to_be_bytes()         (23 B)
//! finalize_ns  = base_ns ‖ b"_FINALIZE"                              (32 B)
//! proposal_enc = uvarint(epoch) ‖ uvarint(view) ‖ uvarint(parent) ‖ digest[32]
//! signed_msg   = uvarint(finalize_ns.len) ‖ finalize_ns ‖ proposal_enc   (union_unique)
//! hm           = hash_to_G1(signed_msg, DST)            // RFC 9380 SSWU_RO, SHA-256
//! verify       = e(hm, Σ pkᵢ) · e(sig, −G2::gen) == 1   // MinSig: sig∈G1, pk∈G2
//! ```
//!
//! `uvarint` = unsigned LEB128 (commonware `codec::varint::UInt`). Signer bitmap
//! is LSB-first (`commonware_utils::BitMap`); bit `i` selects committee member
//! `i` in **commonware-sorted order** (ascending by 32-byte peer pubkey). Quorum
//! is N3f1: `n − (n−1)/3`.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use alloy_primitives::B256;
use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt,
};
use sha2::Sha256;

mod committee;
pub use committee::{committee_snapshot_zk, CommitteeError, StateView};

/// RFC 9380 domain-separation tag for BLS signatures hashed to G1 (commonware
/// `G1_MESSAGE`). Consensus-critical: MUST byte-match the Engine's signing DST.
pub const DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";

/// Compressed BLS12-381 lengths (MinSig): public key ∈ G2, signature ∈ G1.
pub const BLS_PUBKEY_LEN: usize = 96;
pub const BLS_SIG_LEN: usize = 48;

/// One committee member's consensus identity, BLS key pre-decoded to a
/// subgroup-checked affine G2 point.
#[derive(Clone, Debug)]
pub struct ZkValidator {
    /// 32-byte ed25519 peer pubkey — the commonware participant-ordering key.
    pub peer: [u8; 32],
    /// On-chain `blsPubkey` (96-B compressed G2), decoded + subgroup-checked.
    pub bls_g2: G2Affine,
}

impl ZkValidator {
    /// Decode a member from its peer key + 96-B compressed G2 BLS pubkey
    /// (subgroup-checked). Keeps the `bls12_381` types out of callers.
    pub fn from_compressed(
        peer: [u8; 32],
        bls_g2_compressed: &[u8; BLS_PUBKEY_LEN],
    ) -> Result<Self, Error> {
        let bls_g2 = Option::from(G2Affine::from_compressed(bls_g2_compressed))
            .ok_or(Error::BadCommitteeKey)?;
        Ok(Self { peer, bls_g2 })
    }
}

/// A frozen epoch committee, stored in **commonware-sorted order** (ascending by
/// `peer`) so signer-bitmap index `i` maps to `validators[i]`.
#[derive(Clone, Debug)]
pub struct ZkCommittee {
    pub epoch: u64,
    pub validators: Vec<ZkValidator>,
}

impl ZkCommittee {
    /// Sort `validators` into commonware participant order (ascending peer key).
    /// Idempotent; callers may pass contract order.
    pub fn new_sorted(epoch: u64, mut validators: Vec<ZkValidator>) -> Self {
        validators.sort_by_key(|v| v.peer);
        Self { epoch, validators }
    }
}

/// Every variant means the cert is not a valid quorum finalization of
/// `block_hash` by `committee` ⇒ the caller MUST refuse to attest / prove.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Bitmap byte length ≠ `ceil(n/8)` (commonware rejects `signers.len() != n`).
    BitmapLen { expected: usize, got: usize },
    /// A set bit at index ≥ `n` (phantom signer past the committee).
    PhantomSigner(usize),
    /// Signer count below the N3f1 quorum `n − (n−1)/3`.
    BelowQuorum { have: usize, need: usize },
    /// Signature bytes are not a valid compressed G1 point.
    BadSignature,
    /// A committee BLS pubkey is not a valid compressed G2 point.
    BadCommitteeKey,
    /// Aggregate pairing check failed (wrong committee / message / signature).
    PairingFailed,
}

/// LSB-first unsigned LEB128, matching commonware `codec::varint::UInt`.
fn write_uvarint(mut v: u64, out: &mut Vec<u8>) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Reconstruct the exact bytes the Engine hashed to G1 for this finalization.
/// See the module-level layout doc; pinned against commonware in `tests/equiv.rs`.
pub fn build_signed_message(
    chain_id: u64,
    round_epoch: u64,
    round_view: u64,
    parent_view: u64,
    block_hash: B256,
) -> Vec<u8> {
    let mut finalize_ns = Vec::with_capacity(32);
    finalize_ns.extend_from_slice(b"FLUENT_DPOS_V1_");
    finalize_ns.extend_from_slice(&chain_id.to_be_bytes());
    finalize_ns.extend_from_slice(b"_FINALIZE");

    let mut proposal = Vec::with_capacity(3 + 32);
    write_uvarint(round_epoch, &mut proposal);
    write_uvarint(round_view, &mut proposal);
    write_uvarint(parent_view, &mut proposal);
    proposal.extend_from_slice(block_hash.as_slice());

    // union_unique(finalize_ns, proposal): uvarint(len) ‖ ns ‖ msg.
    let mut msg = Vec::with_capacity(1 + finalize_ns.len() + proposal.len());
    write_uvarint(finalize_ns.len() as u64, &mut msg);
    msg.extend_from_slice(&finalize_ns);
    msg.extend_from_slice(&proposal);
    msg
}

/// Verify that `block_hash` is finalized by a quorum of `committee` for the
/// given round. `sig_g1`/`bitmap` come from the host proxy's transcode of the
/// commonware `Finalization` (NOT a trust point — every byte is re-checked here).
#[allow(clippy::too_many_arguments)]
pub fn verify_finalization(
    committee: &ZkCommittee,
    chain_id: u64,
    round_epoch: u64,
    round_view: u64,
    parent_view: u64,
    block_hash: B256,
    sig_g1: &[u8; BLS_SIG_LEN],
    bitmap: &[u8],
) -> Result<(), Error> {
    let n = committee.validators.len();

    // An empty committee has no quorum: `need` below would be 0, and a 0-signer
    // bitmap + identity signature would otherwise pair to identity and "verify".
    // Reject up front so a missing/empty committee can never finalize a block.
    if n == 0 {
        return Err(Error::BelowQuorum { have: 0, need: 1 });
    }

    // 0. Bitmap length must encode exactly n bits (reject short/long).
    let expected = n.div_ceil(8);
    if bitmap.len() != expected {
        return Err(Error::BitmapLen { expected, got: bitmap.len() });
    }

    // 1-2. Walk set bits: reject phantom signers (≥ n), aggregate the selected
    //      committee G2 pubkeys, count the quorum.
    let mut agg = G2Projective::identity();
    let mut count = 0usize;
    for i in 0..bitmap.len() * 8 {
        if (bitmap[i / 8] >> (i % 8)) & 1 == 1 {
            if i >= n {
                return Err(Error::PhantomSigner(i));
            }
            agg += G2Projective::from(committee.validators[i].bls_g2);
            count += 1;
        }
    }
    let need = n - (n.saturating_sub(1) / 3); // N3f1
    if count < need {
        return Err(Error::BelowQuorum { have: count, need });
    }

    // 3. Decode the aggregate signature (compressed G1, subgroup-checked).
    let sig: G1Affine =
        Option::from(G1Affine::from_compressed(sig_g1)).ok_or(Error::BadSignature)?;

    // 4. Hash the reconstructed message to G1.
    let msg = build_signed_message(chain_id, round_epoch, round_view, parent_view, block_hash);
    let hm = G1Affine::from(<G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
        [msg.as_slice()],
        DST,
    ));

    // 5. e(hm, Σpk) · e(sig, −G2::gen) == 1.
    let agg_aff = G2Affine::from(agg);
    let neg_g2 = G2Prepared::from(-G2Affine::generator());
    let result = multi_miller_loop(&[(&hm, &G2Prepared::from(agg_aff)), (&sig, &neg_g2)])
        .final_exponentiation();

    if result == Gt::identity() {
        Ok(())
    } else {
        Err(Error::PairingFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_committee_is_rejected() {
        // n == 0 must fail before the degenerate `need == 0` path; the sig and
        // bitmap are never decoded, so any bytes (here a zero sig + empty bitmap)
        // exercise the guard.
        let committee = ZkCommittee { epoch: 0, validators: Vec::new() };
        let err = verify_finalization(&committee, 1, 0, 0, 0, B256::ZERO, &[0u8; BLS_SIG_LEN], &[])
            .unwrap_err();
        assert_eq!(err, Error::BelowQuorum { have: 0, need: 1 });
    }
}
