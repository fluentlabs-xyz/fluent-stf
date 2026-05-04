//! Mirror of `Rollup.sol`'s `_computeCommitment`, `_calculateBatchRoot`,
//! and `MerkleTree.verifyMerkleProof` — host-side leaf compute, root
//! compute, and inclusion-proof generation.
//!
//! Single source of truth shared between the enclave (`bin/client`) and
//! the host orchestrator (`bin/witness-orchestrator`). Solidity reference:
//! `contracts/libraries/MerkleTree.sol` and
//! `contracts/rollup/Rollup.sol::_computeCommitment` /
//! `_calculateBatchRoot`.

use alloy_primitives::{keccak256, B256};

/// keccak256(left ‖ right). Matches `MerkleTree._efficientHash`.
pub fn keccak_pair(left: B256, right: B256) -> B256 {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left.as_slice());
    buf[32..].copy_from_slice(right.as_slice());
    keccak256(buf)
}

/// `_computeCommitment(L2BlockHeader)` — keccak of the four `bytes32`
/// fields, in struct-declaration order. `depositCount` is in the struct
/// but NOT part of the commitment hash.
pub fn compute_leaf(
    previous_block_hash: B256,
    block_hash: B256,
    withdrawal_root: B256,
    deposit_root: B256,
) -> B256 {
    let mut buf = [0u8; 128];
    buf[..32].copy_from_slice(previous_block_hash.as_slice());
    buf[32..64].copy_from_slice(block_hash.as_slice());
    buf[64..96].copy_from_slice(withdrawal_root.as_slice());
    buf[96..].copy_from_slice(deposit_root.as_slice());
    keccak256(buf)
}

/// `_calculateBatchRoot` — builds a balanced merkle tree where odd-count
/// layers duplicate the last leaf and re-hash with itself. Panics on
/// empty input; that case is invalid for this tree (a batch always has
/// at least one block).
pub fn calculate_merkle_root(leaves: &[B256]) -> B256 {
    assert!(!leaves.is_empty(), "batch-merkle: no leaves provided");
    if leaves.len() == 1 {
        return leaves[0];
    }
    let mut layer: Vec<B256> = leaves.to_vec();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for pair in layer.chunks(2) {
            match pair {
                [a, b] => next.push(keccak_pair(*a, *b)),
                [a] => next.push(keccak_pair(*a, *a)),
                _ => unreachable!("chunks(2) yields slices of length 1 or 2"),
            }
        }
        layer = next;
    }
    layer[0]
}

/// Build an inclusion proof for `leaves[index]` matching the layout
/// consumed by `MerkleTree.verifyMerkleProof`:
///   - returned `nonce` is the leaf index;
///   - returned `proof` is a packed (`Vec<u8>`) sequence of 32-byte sibling hashes from leaf to
///     root.
///
/// Odd-count layers duplicate the last leaf, so the lone leaf's sibling
/// at that layer is itself.
pub fn build_merkle_proof(leaves: &[B256], index: usize) -> (u64, Vec<u8>) {
    assert!(index < leaves.len(), "batch-merkle: index out of bounds");
    let mut proof = Vec::new();
    let mut layer: Vec<B256> = leaves.to_vec();
    let mut idx = index;
    while layer.len() > 1 {
        let sibling_idx = if idx.is_multiple_of(2) {
            // Left child: sibling is the next slot, or self if we're the
            // dangling odd leaf at this layer.
            (idx + 1).min(layer.len() - 1)
        } else {
            // Right child: sibling is always the previous slot.
            idx - 1
        };
        proof.extend_from_slice(layer[sibling_idx].as_slice());

        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for pair in layer.chunks(2) {
            match pair {
                [a, b] => next.push(keccak_pair(*a, *b)),
                [a] => next.push(keccak_pair(*a, *a)),
                _ => unreachable!("chunks(2) yields slices of length 1 or 2"),
            }
        }
        layer = next;
        idx /= 2;
    }
    (index as u64, proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(byte: u8) -> B256 {
        B256::from([byte; 32])
    }

    /// Verify an inclusion proof — mirrors `MerkleTree.verifyMerkleProof`.
    /// Used in tests only; production callers submit the `(nonce, proof)`
    /// straight into the contract.
    fn verify_merkle_proof(root: B256, leaf: B256, mut nonce: u64, proof: &[u8]) -> bool {
        assert!(proof.len().is_multiple_of(32), "proof length must be a multiple of 32");
        let mut hash = leaf;
        for chunk in proof.chunks_exact(32) {
            let sibling = B256::from_slice(chunk);
            hash = if nonce.is_multiple_of(2) {
                keccak_pair(hash, sibling)
            } else {
                keccak_pair(sibling, hash)
            };
            nonce /= 2;
        }
        hash == root
    }

    #[test]
    fn keccak_pair_matches_concat_keccak() {
        let a = h(0x01);
        let b = h(0x02);
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(a.as_slice());
        buf[32..].copy_from_slice(b.as_slice());
        assert_eq!(keccak_pair(a, b), keccak256(buf));
    }

    #[test]
    fn compute_leaf_matches_concat_keccak() {
        let p = h(0xaa);
        let bh = h(0xbb);
        let w = h(0xcc);
        let d = h(0xdd);
        let leaf = compute_leaf(p, bh, w, d);
        let mut buf = [0u8; 128];
        buf[..32].copy_from_slice(p.as_slice());
        buf[32..64].copy_from_slice(bh.as_slice());
        buf[64..96].copy_from_slice(w.as_slice());
        buf[96..].copy_from_slice(d.as_slice());
        assert_eq!(leaf, keccak256(buf));
    }

    #[test]
    fn single_leaf_root_equals_leaf() {
        let l = h(0x42);
        assert_eq!(calculate_merkle_root(&[l]), l);
    }

    #[test]
    fn two_leaf_root_equals_pair_hash() {
        let a = h(0x01);
        let b = h(0x02);
        assert_eq!(calculate_merkle_root(&[a, b]), keccak_pair(a, b));
    }

    #[test]
    fn three_leaf_duplicates_last_per_layer() {
        let a = h(0x01);
        let b = h(0x02);
        let c = h(0x03);
        // layer 0: [a, b, c] → odd, c duplicates → layer 1: [keccak(a,b), keccak(c,c)]
        // layer 1: pair-hash → keccak( keccak(a,b), keccak(c,c) )
        let expected = keccak_pair(keccak_pair(a, b), keccak_pair(c, c));
        assert_eq!(calculate_merkle_root(&[a, b, c]), expected);
    }

    #[test]
    fn proof_round_trip_for_every_index_n8() {
        let leaves: Vec<B256> = (0..8).map(|i| h(i as u8 + 1)).collect();
        let root = calculate_merkle_root(&leaves);
        for (i, leaf) in leaves.iter().enumerate() {
            let (nonce, proof) = build_merkle_proof(&leaves, i);
            assert!(verify_merkle_proof(root, *leaf, nonce, &proof), "verify failed for index {i}");
        }
    }

    #[test]
    fn proof_round_trip_odd_counts() {
        for n in [1usize, 3, 5, 7, 11, 13] {
            let leaves: Vec<B256> = (0..n).map(|i| h(i as u8 + 1)).collect();
            let root = calculate_merkle_root(&leaves);
            for i in 0..n {
                let (nonce, proof) = build_merkle_proof(&leaves, i);
                assert!(
                    verify_merkle_proof(root, leaves[i], nonce, &proof),
                    "verify failed for n={n} index={i}"
                );
            }
        }
    }

    #[test]
    #[should_panic(expected = "no leaves provided")]
    fn empty_root_panics() {
        let _ = calculate_merkle_root(&[]);
    }
}
