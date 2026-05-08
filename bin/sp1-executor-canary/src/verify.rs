//! Public-values verification for the SP1 canary.
//!
//! After `client.execute()` returns `Ok`, the guest's committed bytes
//! (`SP1PublicValues::as_slice()`) are parsed by the same field layout
//! the guest writes via `commit_slice` calls in `bin/client/src/sp1.rs`,
//! and each field is compared against an externally-computed expected
//! value. Mismatch = divergence even though the guest did not panic.
//!
//! This is the analog of Groth16 verify, applied without proof
//! generation: `execute()` guarantees the computation ran (or
//! panicked), but only public-values cross-check guarantees the result
//! matches host-side expectations.

use alloy_primitives::B256;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::{db::DivergenceKind, types::BlockExpected};

/// Schema (mirrors `bin/client/src/sp1.rs:96-104`):
///
///   parent_hash(32) || block_hash(32) || withdrawal_hash(32) ||
///   deposit_hash(32) || versioned_hashes[N×32]
pub(crate) fn verify_public_values(
    bytes: &[u8],
    expected: &BlockExpected,
) -> Result<(), (DivergenceKind, String)> {
    let n = expected.versioned_hashes.len();
    let want = 4 * 32 + n * 32;
    if bytes.len() != want {
        return Err((
            DivergenceKind::PublicValuesMismatchLength,
            format!("got {} bytes, expected {want}", bytes.len()),
        ));
    }
    let parent = B256::from_slice(&bytes[0..32]);
    let block_hash = B256::from_slice(&bytes[32..64]);
    let withdrawal = B256::from_slice(&bytes[64..96]);
    let deposit = B256::from_slice(&bytes[96..128]);
    if parent != expected.parent_hash {
        return Err((
            DivergenceKind::PublicValuesMismatchParentHash,
            format!("got {parent}, expected {}", expected.parent_hash),
        ));
    }
    if block_hash != expected.block_hash {
        return Err((
            DivergenceKind::PublicValuesMismatchBlockHash,
            format!("got {block_hash}, expected {}", expected.block_hash),
        ));
    }
    if withdrawal != expected.withdrawal_hash {
        return Err((
            DivergenceKind::PublicValuesMismatchWithdrawalHash,
            format!("got {withdrawal}, expected {}", expected.withdrawal_hash),
        ));
    }
    if deposit != expected.deposit_hash {
        return Err((
            DivergenceKind::PublicValuesMismatchDepositHash,
            format!("got {deposit}, expected {}", expected.deposit_hash),
        ));
    }
    for i in 0..n {
        let off = 128 + i * 32;
        let actual = B256::from_slice(&bytes[off..off + 32]);
        if actual != expected.versioned_hashes[i] {
            return Err((
                DivergenceKind::PublicValuesMismatchVersionedHash,
                format!("idx {i}: got {actual}, expected {}", expected.versioned_hashes[i]),
            ));
        }
    }
    Ok(())
}

/// KZG-versioned-hash: sha256(commitment) with byte 0 set to 0x01.
/// Mirrors `bin/client/src/sp1.rs:85-89`.
pub(crate) fn versioned_hash(commitment: &[u8]) -> B256 {
    let h = Sha256::digest(commitment);
    let mut out = B256::default();
    out.0[0] = 0x01;
    out.0[1..].copy_from_slice(&h[1..]);
    out
}

pub(crate) fn expected_versioned_hashes(commitments: &[Vec<u8>]) -> Arc<Vec<B256>> {
    Arc::new(commitments.iter().map(|c| versioned_hash(c)).collect())
}
