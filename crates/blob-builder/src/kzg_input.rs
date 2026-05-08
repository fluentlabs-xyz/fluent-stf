//! Build a KZG-validated `BlobVerificationInput` (commitments + proofs
//! computed against the bundled trusted setup) from raw EIP-4844 blob
//! bytes. Shared between bin/proxy (challenge + mock SP1 paths) and
//! bin/sp1-executor-canary.
//!
//! The trusted setup file `bin/client/trusted_setup.txt` is the same
//! one the SP1 ELF embeds at compile time via
//! `KzgSettings::load_trusted_setup_file()`, so host- and guest-side
//! KZG verification share the same parameters.

use c_kzg::{Blob as CKzgBlob, KzgSettings};
use eyre::{eyre, Result};
use nitro_types::BlobVerificationInput;

const TRUSTED_SETUP: &str = include_str!("../../../bin/client/trusted_setup.txt");

pub fn prepare_blob_verification_input(raw_blobs: &[Vec<u8>]) -> Result<BlobVerificationInput> {
    let settings = KzgSettings::parse_kzg_trusted_setup(TRUSTED_SETUP, 0)
        .map_err(|e| eyre!("Failed to parse KZG settings: {e}"))?;

    let mut commitments = Vec::with_capacity(raw_blobs.len());
    let mut proofs = Vec::with_capacity(raw_blobs.len());

    for raw in raw_blobs {
        let blob = CKzgBlob::from_bytes(raw).map_err(|e| eyre!("Invalid blob bytes: {e}"))?;
        let commitment = settings
            .blob_to_kzg_commitment(&blob)
            .map_err(|e| eyre!("KZG commitment failed: {e}"))?;
        let commitment_bytes = commitment.to_bytes();
        let proof = settings
            .compute_blob_kzg_proof(&blob, &commitment_bytes)
            .map_err(|e| eyre!("KZG proof generation failed: {e}"))?;
        commitments.push(commitment_bytes.to_vec());
        proofs.push(proof.to_bytes().to_vec());
    }

    Ok(BlobVerificationInput { blobs: raw_blobs.to_vec(), commitments, proofs })
}
