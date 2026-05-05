// ---------------------------------------------------------------------------
// SP1 proof result
// ---------------------------------------------------------------------------

/// Wire payload for `/challenge/sp1/status` 200 response. The Rollup
/// contract reconstructs `publicValues` itself from the block header +
/// blob hashes, so the orchestrator only needs `proof_bytes` — the Groth16
/// proof passed to `ISP1Verifier.verifyProof`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct Sp1ProofResponse {
    pub proof_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Nitro enclave configuration
// ---------------------------------------------------------------------------

/// Runtime parameters for the AWS Nitro Enclave process.
///
/// Passed to `nitro-cli run-enclave` on startup and reused when opening
/// VSOCK connections to the running enclave.
#[derive(Debug, Clone, Copy)]
pub(crate) struct NitroConfig {
    /// VSOCK Context ID assigned to the enclave (`--enclave-cid`).
    pub enclave_cid: u32,
    /// VSOCK port the enclave listens on for execution requests.
    pub enclave_port: u32,
}

impl Default for NitroConfig {
    fn default() -> Self {
        Self { enclave_cid: 10, enclave_port: 5005 }
    }
}
