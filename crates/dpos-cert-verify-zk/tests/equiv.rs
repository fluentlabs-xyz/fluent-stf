//! Phase-0a/Phase-1 gate: the blst-free verify-core reproduces commonware's
//! verdict on a REAL devnet finalization cert, and the message it hashes is
//! byte-identical to commonware's. This is the oracle that pins the from-scratch
//! BLS path to the canonical implementation.

use alloy_primitives::B256;
use commonware_codec::Encode as _;
use dpos_cert_verify::{decode_finalization, transcode_finalization};
use dpos_cert_verify_zk::{build_signed_message, verify_finalization, ZkCommittee, ZkValidator};
use serde_json::Value;

const FIXTURE: &str = include_str!("fixtures/dpos_finalization.json");

fn hexb(s: &str) -> Vec<u8> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).expect("hex")
}

struct Parsed {
    committee: ZkCommittee,
    chain_id: u64,
    epoch: u64,
    view: u64,
    parent: u64,
    digest: B256,
    sig: [u8; 48],
    bitmap: Vec<u8>,
    cert: Vec<u8>,
}

fn parse() -> Parsed {
    let v: Value = serde_json::from_str(FIXTURE).expect("fixture json");
    let chain_id = v["chain_id"].as_u64().unwrap();
    let digest = B256::from_slice(&hexb(v["digest"].as_str().unwrap()));
    let cert = hexb(v["certificate"].as_str().unwrap());

    // Committee in contract order → ZkCommittee re-sorts by peer key.
    let validators = v["committee"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            let peer: [u8; 32] = hexb(m["peer_pubkey"].as_str().unwrap()).try_into().unwrap();
            let bls = hexb(m["bls_pubkey"].as_str().unwrap());
            let bls_g2 = Option::from(bls12_381::G2Affine::from_compressed(
                &<[u8; 96]>::try_from(bls.as_slice()).unwrap(),
            ))
            .expect("committee bls pubkey is a valid G2 point");
            ZkValidator { peer, bls_g2 }
        })
        .collect();
    let n = v["committee"].as_array().unwrap().len();
    let committee = ZkCommittee::new_sorted(v["epoch"].as_u64().unwrap(), validators);

    // Transcode the commonware cert into raw points — the proxy's Phase-2 job.
    let parts = transcode_finalization(&cert, n).expect("transcode");

    Parsed {
        committee,
        chain_id,
        epoch: parts.round_epoch,
        view: parts.round_view,
        parent: parts.parent_view,
        digest,
        sig: parts.sig_g1,
        bitmap: parts.bitmap,
        cert,
    }
}

#[test]
fn zk_message_matches_commonware_byte_for_byte() {
    let p = parse();
    let decoded = decode_finalization(&p.cert, p.committee.validators.len()).unwrap();

    // commonware's signed bytes = union_unique(finalize_ns, proposal.encode()).
    let mut finalize_ns = Vec::new();
    finalize_ns.extend_from_slice(b"FLUENT_DPOS_V1_");
    finalize_ns.extend_from_slice(&p.chain_id.to_be_bytes());
    finalize_ns.extend_from_slice(b"_FINALIZE");
    let cw_msg = commonware_utils::union_unique(&finalize_ns, &decoded.proposal.encode());

    let zk_msg = build_signed_message(p.chain_id, p.epoch, p.view, p.parent, p.digest);
    assert_eq!(zk_msg, cw_msg, "blst-free message reconstruction must match commonware");
}

#[test]
fn zk_verifies_real_cert() {
    let p = parse();
    verify_finalization(
        &p.committee,
        p.chain_id,
        p.epoch,
        p.view,
        p.parent,
        p.digest,
        &p.sig,
        &p.bitmap,
    )
    .expect("blst-free core must accept the real finalization cert");
}

#[test]
fn zk_rejects_tampered_signature() {
    let mut p = parse();
    p.sig[10] ^= 0x01;
    assert!(
        verify_finalization(
            &p.committee,
            p.chain_id,
            p.epoch,
            p.view,
            p.parent,
            p.digest,
            &p.sig,
            &p.bitmap,
        )
        .is_err(),
        "a one-bit-flipped signature must fail the pairing"
    );
}

#[test]
fn zk_rejects_wrong_digest() {
    let p = parse();
    let wrong = B256::repeat_byte(0xab);
    assert!(
        verify_finalization(
            &p.committee,
            p.chain_id,
            p.epoch,
            p.view,
            p.parent,
            wrong,
            &p.sig,
            &p.bitmap,
        )
        .is_err(),
        "verifying against a different block digest must fail"
    );
}
