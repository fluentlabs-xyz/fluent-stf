#[cfg(not(test))]
sp1_zkvm::entrypoint!(main);

#[cfg(target_os = "zkvm")]
use rsp_client_executor::executor::DESERIALZE_INPUTS;
use rsp_client_executor::{
    executor::EthClientExecutor, io::EthClientExecutorInput, utils::profile_report,
};

use alloy_primitives::B256;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use kzg_rs::{Blob, Bytes48, KzgProof, KzgSettings};

use crate::blob;
use dpos_cert_verify_zk::verify_finalization;
use nitro_types::{BlobVerificationInput, CertVerifyInput};

/// Upper bound on a bincode-serialized `EthClientExecutorInput` / `BlobVerificationInput`
/// the guest is willing to decode. Bounds memory allocation during deserialization
/// so a malicious host cannot force the zkVM to allocate unbounded buffers.
const MAX_INPUT_SIZE: u64 = 256 * 1024 * 1024;

pub fn main() {
    // 1. Read and deserialize inputs using read_vec
    let (executor_input, blob_input, cert_input) = profile_report!(DESERIALZE_INPUTS, {
        use bincode::Options as _;
        let opts = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_limit(MAX_INPUT_SIZE);

        let exec_bytes = sp1_zkvm::io::read_vec();
        let exec_input = opts.deserialize::<EthClientExecutorInput>(&exec_bytes).unwrap();

        let blob_bytes = sp1_zkvm::io::read_vec();
        let blob_input = opts.deserialize::<BlobVerificationInput>(&blob_bytes).unwrap();

        // Input #3: the proxy-transcoded finalization cert. Empty pre-activation
        // / when no cert is supplied (the host always writes this slot).
        let cert_bytes = sp1_zkvm::io::read_vec();
        let cert_input = (!cert_bytes.is_empty())
            .then(|| opts.deserialize::<CertVerifyInput>(&cert_bytes).unwrap());

        (exec_input, blob_input, cert_input)
    });

    // Load pre-compiled Trusted Setup from the crate's internal binary storage (Zero-Copy)
    let kzg_settings =
        KzgSettings::load_trusted_setup_file().expect("Failed to load embedded trusted setup");

    // 2. Execute STF first — the heaviest phase runs with minimal live heap.
    let executor = EthClientExecutor::eth(
        Arc::new(fluent_stf_primitives::fluent_chainspec()),
        executor_input.custom_beneficiary,
    );

    // DPoS committee read happens BEFORE `execute` consumes `executor_input`:
    // the committee is read from the witnessed pre-state (the trust anchor), then
    // the cert is verified against the EXECUTED block hash below. `None` when no
    // cert was supplied or the block precedes DPoS activation.
    let block_number = executor_input.current_block.header.number;
    // Mirror of the enclave gate: once DPoS is active the guest must NOT prove a
    // block without a finalization cert. Panic ⇒ proof refused.
    assert!(
        cert_input.is_some() || !fluent_stf_primitives::dpos_active(block_number),
        "DPoS active (block {block_number}): finalization cert required",
    );
    let dpos_committee = cert_input.as_ref().and_then(|_| {
        fluent_stf_primitives::dpos_active(block_number).then(|| {
            let epoch = fluent_stf_primitives::epoch_of_block(
                block_number,
                fluent_stf_primitives::EPOCH_BLOCK_INTERVAL,
                fluent_stf_primitives::DPOS_ACTIVATION_BLOCK,
            );
            let snapshot = crate::dpos_committee::read_zk_committee(
                &executor_input,
                Arc::new(fluent_stf_primitives::fluent_chainspec()),
                epoch,
                fluent_stf_primitives::DPOS_STAKING_ADDRESS,
            )
            .expect("DPoS committee read from witnessed pre-state failed");
            (epoch, snapshot)
        })
    });

    let (header, events_hash) = executor.execute(executor_input).expect("STF execution failed");
    let stf_block_hash = header.hash_slow();

    // Verify the finalization cert against the committee read from pre-state and
    // the EXECUTED block hash. A divergent branch cannot produce a cert that
    // passes here, so it is never proven. Panic ⇒ proof refused.
    if let (Some(cert), Some((epoch, committee))) = (cert_input.as_ref(), dpos_committee.as_ref()) {
        assert_eq!(cert.round_epoch, *epoch, "cert round epoch != block epoch");
        verify_finalization(
            committee,
            fluent_stf_primitives::FLUENT_CHAIN_ID,
            cert.round_epoch,
            cert.round_view,
            cert.parent_view,
            stf_block_hash,
            &cert.sig_g1,
            &cert.bitmap,
        )
        .expect("DPoS committee cert verification failed");
    }

    // 3. Decanonicalize + brotli-decompress the blob AFTER STF: defers decompression cost past any
    //    early STF panic and keeps the brotli- output buffer out of the hottest allocation phase.
    {
        let decompressed = blob::decode_blob_payload(&blob_input.blobs).unwrap();

        // 4. Bind blob ↔ STF via block_hash equality on the target block.
        let found = blob::iter_blocks(&decompressed)
            .any(|view| matches!(view, Ok(v) if v.block_hash == stf_block_hash));
        assert!(found, "DA/STF block_hash mismatch: target block not found in blob");
        // `decompressed` dropped here before KZG verification.
    }

    // 5. KZG Verification (Using pre-computed host witnesses)
    assert_eq!(
        blob_input.blobs.len(),
        blob_input.commitments.len(),
        "blobs / commitments length mismatch"
    );
    assert_eq!(blob_input.blobs.len(), blob_input.proofs.len(), "blobs / proofs length mismatch");
    let mut versioned_hashes = Vec::with_capacity(blob_input.commitments.len());
    for i in 0..blob_input.blobs.len() {
        let blob = Blob::from_slice(&blob_input.blobs[i]).expect("Invalid blob slice");
        let commitment =
            Bytes48::from_slice(&blob_input.commitments[i]).expect("Invalid commitment slice");
        let proof = Bytes48::from_slice(&blob_input.proofs[i]).expect("Invalid proof slice");

        let is_valid = KzgProof::verify_blob_kzg_proof(blob, &commitment, &proof, &kzg_settings)
            .expect("KZG internal error");

        assert!(is_valid, "KZG verification failed at blob index {i}");

        let hash = Sha256::digest(commitment.as_slice());
        let mut vh = B256::default();
        vh.0[0] = 0x01;
        vh.0[1..].copy_from_slice(&hash[1..]);
        versioned_hashes.push(vh);
    }

    // 6. Commit results for L1 Verifier
    // Use commit_slice (raw bytes) instead of commit (bincode) so the public
    // values match the flat abi.encodePacked layout expected by
    // Rollup._proveBlockWithSp1:
    //   previousBlockHash(32) || blockHash(32) || withdrawalRoot(32)
    //   || depositRoot(32) || blobHashes[0](32) || … || blobHashes[N](32)
    sp1_zkvm::io::commit_slice(header.parent_hash.as_slice());
    sp1_zkvm::io::commit_slice(stf_block_hash.as_slice());
    sp1_zkvm::io::commit_slice(events_hash.withdrawal_hash.as_slice());
    sp1_zkvm::io::commit_slice(events_hash.deposit_hash.as_slice());
    for vh in &versioned_hashes {
        sp1_zkvm::io::commit_slice(vh.as_slice());
    }
}
