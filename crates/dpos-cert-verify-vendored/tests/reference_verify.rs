//! Phase-0a reference gate: a REAL commonware-signed DPoS finalization cert
//! (pulled from the `local-dpos-smoke` devnet via `consensus_getFinalization`)
//! MUST verify against the on-chain epoch committee it was signed by, and a
//! tampered cert MUST be rejected. This pins the commonware verdict the
//! zkcrypto verify-core (Phase 1) is later required to reproduce byte-for-byte.

use alloy_primitives::{Address, B256};
use commonware_codec::DecodeExt as _;
use dpos_cert_verify::{
    decode_finalization, transcode_finalization, verify_cert_with_snapshot, BlsPubkey,
    ConsensusKeys, Digest, PeerPubkey, ValidatorSetSnapshot, ValidatorWithKeys,
};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use serde_json::Value;

const FIXTURE: &str = include_str!("fixtures/dpos_finalization.json");

fn hexb(s: &str) -> Vec<u8> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).expect("hex")
}

/// Rebuild the verifier inputs from the fixture: the on-chain committee (in
/// contract order — commonware re-sorts internally), the chain id, the signed
/// block digest, and the raw cert bytes.
fn load() -> (ValidatorSetSnapshot, u64, B256, Vec<u8>) {
    let v: Value = serde_json::from_str(FIXTURE).expect("fixture json");
    let chain_id = v["chain_id"].as_u64().unwrap();
    let epoch = v["epoch"].as_u64().unwrap();
    let block_number = v["height"].as_u64().unwrap();
    let digest = B256::from_slice(&hexb(v["digest"].as_str().unwrap()));
    let cert = hexb(v["certificate"].as_str().unwrap());

    let validators = v["committee"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            let address: Address = m["address"].as_str().unwrap().parse().unwrap();
            let bls_pubkey = BlsPubkey::decode(hexb(m["bls_pubkey"].as_str().unwrap()).as_ref())
                .expect("bls pubkey decode (96B G2, subgroup-checked)");
            let peer_pubkey =
                PeerPubkey::decode(hexb(m["peer_pubkey"].as_str().unwrap()).as_slice())
                    .expect("peer pubkey decode (32B ed25519)");
            let activation_epoch = m["activation_epoch"].as_u64().unwrap();
            ValidatorWithKeys {
                address,
                keys: ConsensusKeys { bls_pubkey, peer_pubkey, activation_epoch },
            }
        })
        .collect();

    let snap = ValidatorSetSnapshot { block_hash: digest, block_number, epoch, validators };
    (snap, chain_id, digest, cert)
}

#[test]
fn real_finalization_cert_verifies_against_committee() {
    let (snap, chain_id, digest, cert) = load();
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    verify_cert_with_snapshot(&snap, chain_id, digest, &cert, &mut rng)
        .expect("real DPoS finalization cert must verify against its on-chain committee");
}

#[test]
fn tampered_cert_is_rejected() {
    let (snap, chain_id, digest, mut cert) = load();
    // Flip one bit inside the aggregate-signature region (past the proposal
    // prefix + digest): the BLS multisig must no longer verify.
    let i = cert.len() - 8;
    cert[i] ^= 0x01;
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    assert!(
        verify_cert_with_snapshot(&snap, chain_id, digest, &cert, &mut rng).is_err(),
        "a one-bit-flipped cert must be rejected"
    );
}

#[test]
fn cert_payload_binds_block_digest() {
    let (snap, _chain_id, digest, cert) = load();
    let decoded = decode_finalization(&cert, snap.validators.len()).expect("cert decode");
    assert_eq!(
        decoded.proposal.payload,
        Digest(digest),
        "the cert's proposal payload IS the block digest (state-root-anchored binding)"
    );
}

#[test]
fn transcode_extracts_raw_parts() {
    let (snap, _chain_id, _digest, cert) = load();
    let parts = transcode_finalization(&cert, snap.validators.len()).expect("transcode");
    // block 486 epoch 13 view 12 parent 11; 3-of-4 signers → bitmap 0b1101 = 0x0d.
    assert_eq!(parts.round_epoch, 13);
    assert_eq!(parts.round_view, 12);
    assert_eq!(parts.parent_view, 11);
    assert_eq!(parts.bitmap, vec![0x0d]);
    assert_eq!(&parts.sig_g1[..], &cert[cert.len() - 48..]);
}
