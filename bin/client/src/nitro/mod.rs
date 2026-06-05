mod kms;
mod params;
mod vsock_channel;

use anyhow::Context;
use hkdf::Hkdf;
pub use params::*;

use aws_nitro_enclaves_nsm_api::{
    api::{Request, Response},
    driver,
};

use k256::{
    ecdsa::{
        signature::{Signer, Verifier},
        RecoveryId, Signature, SigningKey, VerifyingKey,
    },
    elliptic_curve::scalar::IsHigh,
    SecretKey,
};

use alloy_primitives::{Address, B256};
use c_kzg::{Blob, KzgSettings, BYTES_PER_BLOB};

use dpos_cert_verify_zk::verify_finalization;
use fluent_stf_primitives::{L1_CHAIN_ID, NITRO_VERIFIER_ADDRESS};
use nitro_types::{
    CertVerifyInput, EnclaveIncoming, EnclaveResponse, EthExecutionResponse, SubmitBatchResponse,
};
use rsp_client_executor::{executor::EthClientExecutor, io::EthClientExecutorInput};

use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use std::{
    collections::BTreeMap,
    sync::{
        mpsc::{sync_channel, Receiver, SyncSender, TrySendError},
        Arc, LazyLock, Mutex,
    },
    thread,
    time::Duration,
};
use vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};

use crate::{
    blob,
    nitro::{kms::KmsClient, vsock_channel::VsockChannel},
};

// ---------------------------------------------------------------------------
// KZG trusted setup (Ethereum ceremony)
// ---------------------------------------------------------------------------

const TRUSTED_SETUP_BYTES: &[u8] = include_bytes!("../../trusted_setup.txt");

static KZG_SETTINGS: LazyLock<KzgSettings> = LazyLock::new(|| {
    let setup_str =
        std::str::from_utf8(TRUSTED_SETUP_BYTES).expect("trusted setup is not valid UTF-8");
    KzgSettings::parse_kzg_trusted_setup(setup_str, 0).expect("failed to load KZG trusted setup")
});

/// Computes versioned_hash = 0x01 || SHA256(KZG_commitment)[1..]
fn blob_to_versioned_hash(blob_bytes: &[u8; BYTES_PER_BLOB]) -> anyhow::Result<B256> {
    let blob =
        Blob::from_bytes(blob_bytes).map_err(|e| anyhow::anyhow!("invalid blob bytes: {e}"))?;
    let commitment = KZG_SETTINGS
        .blob_to_kzg_commitment(&blob)
        .map_err(|e| anyhow::anyhow!("KZG commitment failed: {e}"))?;

    let hash = Sha256::digest(commitment.as_ref());

    let mut vh = B256::default();
    vh.0[0] = 0x01; // EIP-4844 version byte
    vh.0[1..].copy_from_slice(&hash[1..]);
    Ok(vh)
}

/// Computes KZG versioned hashes for all blobs.
fn compute_versioned_hashes(blobs: &[Vec<u8>]) -> anyhow::Result<Vec<B256>> {
    let mut versioned_hashes = Vec::with_capacity(blobs.len());
    for (i, blob) in blobs.iter().enumerate() {
        let arr: &[u8; BYTES_PER_BLOB] = blob
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("blob {i} must be exactly {BYTES_PER_BLOB} bytes"))?;
        versioned_hashes.push(blob_to_versioned_hash(arr)?);
    }
    Ok(versioned_hashes)
}

// ---------------------------------------------------------------------------
// BlockStore — keeps the last MAX_ENTRIES Merkle leaves + block_hashes
// ---------------------------------------------------------------------------

const MAX_ENTRIES: usize = 1 << 18;

/// Per-block data stored after execution.
#[derive(Clone, Copy)]
pub(crate) struct BlockEntry {
    /// keccak256(parent ‖ block ‖ withdrawal ‖ deposit)
    leaf: [u8; 32],
    /// alloy_consensus::Header::hash_slow() of the executed block.
    block_hash: B256,
}

pub(crate) struct BlockStore {
    entries: BTreeMap<u64, BlockEntry>,
}

impl BlockStore {
    pub(crate) fn new() -> Self {
        Self { entries: BTreeMap::new() }
    }

    pub(crate) fn get(&self, block_number: u64) -> Option<&BlockEntry> {
        self.entries.get(&block_number)
    }

    pub(crate) fn insert(&mut self, block_number: u64, entry: BlockEntry) {
        self.entries.insert(block_number, entry);

        while self.entries.len() > MAX_ENTRIES {
            let oldest = *self.entries.keys().next().unwrap();
            self.entries.remove(&oldest);
        }
    }
}

// ---------------------------------------------------------------------------
// Merkle root + leaf compute
// ---------------------------------------------------------------------------
// Source of truth lives in `batch_merkle` (shared with the host
// orchestrator). The wrappers below adapt `[u8; 32]` ↔ `B256`.

fn calculate_merkle_root(leaves: &[[u8; 32]]) -> anyhow::Result<[u8; 32]> {
    anyhow::ensure!(!leaves.is_empty(), "no leaves provided");
    let leaves_b256: Vec<B256> = leaves.iter().copied().map(B256::from).collect();
    Ok(batch_merkle::calculate_merkle_root(&leaves_b256).0)
}

fn compute_leaf(
    parent_hash: &[u8],
    block_hash: &[u8],
    withdrawal_hash: &[u8],
    deposit_hash: &[u8],
) -> [u8; 32] {
    batch_merkle::compute_leaf(
        B256::from_slice(parent_hash),
        B256::from_slice(block_hash),
        B256::from_slice(withdrawal_hash),
        B256::from_slice(deposit_hash),
    )
    .0
}

// ---------------------------------------------------------------------------
// Signature verification for EthExecutionResponse
// ---------------------------------------------------------------------------

/// Payload layout signed by `sign_execution` / checked by `verify_response`.
/// `block_number` is committed alongside `(leaf, block_hash)` so a response
/// signed for block N cannot be replayed under a different block number when
/// SubmitBatch falls back to responses on cache miss.
fn execution_sign_payload(block_number: u64, leaf: &[u8; 32], block_hash: &B256) -> [u8; 72] {
    let mut payload = [0u8; 72];
    payload[..8].copy_from_slice(&block_number.to_be_bytes());
    payload[8..40].copy_from_slice(leaf);
    payload[40..].copy_from_slice(block_hash.as_slice());
    payload
}

/// Verifies that an EthExecutionResponse was signed by this enclave for the
/// specific block_number the response claims to represent.
fn verify_response(
    resp: &EthExecutionResponse,
    verifying_key: &VerifyingKey,
) -> anyhow::Result<()> {
    let payload = execution_sign_payload(resp.block_number, &resp.leaf, &resp.block_hash);
    let signature = Signature::from_slice(&resp.signature).context("invalid signature encoding")?;
    verifying_key.verify(&payload, &signature).context("signature verification failed")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Blob verification
// ---------------------------------------------------------------------------

/// Verifies all blobs against a trusted list of per-block `block_hash`es and
/// returns versioned hashes.
///
/// `block_hashes[i]` is the trusted hash for the i-th block in the blob
/// payload. Sources: the in-memory BlockStore (cache hit) or verified
/// EthExecutionResponses (cache miss). The payload is
/// `brotli(rlp(Block_1) || ... || rlp(Block_N))` — we walk it in lockstep
/// with `block_hashes` and assert per-position equality.
fn verify_blobs(blobs: &[Vec<u8>], block_hashes: &[B256]) -> anyhow::Result<Vec<B256>> {
    let decompressed = blob::decode_blob_payload(blobs).map_err(|e| anyhow::anyhow!("{e}"))?;

    let mut iter = blob::iter_blocks(&decompressed);
    for (i, expected) in block_hashes.iter().enumerate() {
        let view = iter
            .next()
            .ok_or_else(|| anyhow::anyhow!("blob truncated: missing block at index {i}"))?
            .map_err(|e| anyhow::anyhow!("blob decode at index {i}: {e}"))?;
        anyhow::ensure!(
            view.block_hash == *expected,
            "block_hash mismatch at index {i}: blob={}, expected={}",
            view.block_hash,
            expected,
        );
    }
    anyhow::ensure!(iter.next().is_none(), "blob has trailing blocks beyond the trusted list",);

    compute_versioned_hashes(blobs)
}

// ---------------------------------------------------------------------------
// Batch signing
// ---------------------------------------------------------------------------

/// Signs batch_root and versioned_hashes into a SubmitBatchResponse.
/// ABI-encode `(uint256 chainId, address verifier, bytes32 batchRoot, bytes32[] blobHashes)`
/// matching Solidity's `abi.encode(block.chainid, address(this), batchRoot, blobHashes)`
/// in `NitroVerifier.verifyBatch` (domain separation against cross-chain /
/// cross-deployment replay).
///
/// `block.chainid` in Solidity is the L1 chain where `NitroVerifier` is deployed,
/// so we sign under `L1_CHAIN_ID`, not the Fluent L2 chain id.
fn abi_encode_batch(batch_root: &[u8; 32], hashes: &[B256]) -> Vec<u8> {
    // Head: chainId(32) + verifier(32) + batchRoot(32) + offset(32) = 128 bytes
    // Tail: array length(32) + elements(32 * N)
    let mut buf = Vec::with_capacity(128 + 32 + hashes.len() * 32);

    // uint256 chainId — left-padded big-endian
    let mut chain_id_word = [0u8; 32];
    chain_id_word[24..32].copy_from_slice(&L1_CHAIN_ID.to_be_bytes());
    buf.extend_from_slice(&chain_id_word);

    // address verifier — left-padded (12 zero bytes || 20-byte address)
    let mut verifier_word = [0u8; 32];
    verifier_word[12..32].copy_from_slice(&NITRO_VERIFIER_ADDRESS);
    buf.extend_from_slice(&verifier_word);

    // bytes32 batchRoot
    buf.extend_from_slice(batch_root);

    // offset to dynamic array data (head is 4 * 32 = 128 = 0x80)
    let mut offset = [0u8; 32];
    offset[31] = 0x80;
    buf.extend_from_slice(&offset);

    // array length
    let mut len = [0u8; 32];
    let len_bytes = (hashes.len() as u64).to_be_bytes();
    len[24..32].copy_from_slice(&len_bytes);
    buf.extend_from_slice(&len);

    // array elements
    for h in hashes {
        buf.extend_from_slice(h.as_slice());
    }
    buf
}

fn sign_batch(
    batch_root: [u8; 32],
    versioned_hashes: Vec<B256>,
    signing_key: &SigningKey,
) -> SubmitBatchResponse {
    let encoded = abi_encode_batch(&batch_root, &versioned_hashes);
    let digest = Sha256::new_with_prefix(&encoded);
    let (signature, recid): (Signature, RecoveryId) =
        signing_key.sign_digest_recoverable(digest).expect("signing cannot fail with a valid key");

    // Defence-in-depth: k256 0.13.x guarantees low-S from sign_digest_recoverable.
    // If a future upstream version ever regresses, fail loud at signing time rather
    // than silently producing a signature that Solidity's ecrecover rejects or whose
    // recid is now inconsistent after a manual flip.
    assert!(
        !bool::from(signature.s().is_high()),
        "k256 produced high-S signature — upstream regression"
    );

    // Ethereum-compatible 65-byte signature: r (32) || s (32) || v (1)
    let mut sig_bytes = [0u8; 65];
    sig_bytes[..64].copy_from_slice(&signature.to_bytes());
    sig_bytes[64] = recid.to_byte() + 27; // EIP-155: v = recid + 27

    SubmitBatchResponse {
        batch_root: batch_root.to_vec(),
        versioned_hashes,
        signature: sig_bytes.to_vec(),
    }
}

// ---------------------------------------------------------------------------
// SubmitBatch — cache-first with response fallback
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub(crate) enum SubmitBatchError {
    InvalidSignatures(Vec<u64>),
    Other(anyhow::Error),
}

pub(crate) fn handle_submit_batch(
    from: u64,
    to: u64,
    responses: &[EthExecutionResponse],
    blobs: &[Vec<u8>],
    signing_key: &SigningKey,
    block_store: &Mutex<BlockStore>,
) -> Result<SubmitBatchResponse, SubmitBatchError> {
    if from > to {
        return Err(SubmitBatchError::Other(anyhow::anyhow!(
            "invalid batch range: from ({from}) > to ({to})"
        )));
    }

    let verifying_key = *signing_key.verifying_key();

    let mut response_map: std::collections::HashMap<u64, &EthExecutionResponse> =
        std::collections::HashMap::with_capacity(responses.len());
    for resp in responses {
        if response_map.insert(resp.block_number, resp).is_some() {
            return Err(SubmitBatchError::Other(anyhow::anyhow!(
                "duplicate block_number {} in SubmitBatch",
                resp.block_number
            )));
        }
    }

    // Snapshot the cache into an owned vector and drop the guard BEFORE
    // signature verification / Merkle / blob decode — keeps the store
    // available to concurrent ExecuteBlock workers during the heavy work.
    //
    // Semantics: this is a point-in-time view. Any ExecuteBlock worker that
    // inserts into `block_store` for a key in `[from, to]` after the snapshot
    // is intentionally invisible to this in-flight batch; the submitter will
    // see the fresher value on the next SubmitBatch call.
    let cached: Vec<Option<BlockEntry>> = {
        let store = block_store.lock().map_err(|e| {
            SubmitBatchError::Other(anyhow::anyhow!("block_store mutex poisoned: {e}"))
        })?;
        (from..=to).map(|n| store.get(n).copied()).collect()
    };

    let mut leaves = Vec::with_capacity((to - from + 1) as usize);
    let mut block_hashes = Vec::with_capacity((to - from + 1) as usize);
    let mut invalid_blocks: Vec<u64> = Vec::new();

    for (idx, block) in (from..=to).enumerate() {
        if let Some(resp) = response_map.get(&block) {
            if verify_response(resp, &verifying_key).is_ok() {
                leaves.push(resp.leaf);
                block_hashes.push(resp.block_hash);
            } else {
                invalid_blocks.push(block);
            }
        } else if let Some(entry) = cached[idx] {
            leaves.push(entry.leaf);
            block_hashes.push(entry.block_hash);
        } else {
            invalid_blocks.push(block);
        }
    }

    if !invalid_blocks.is_empty() {
        return Err(SubmitBatchError::InvalidSignatures(invalid_blocks));
    }

    let batch_root = calculate_merkle_root(&leaves).map_err(SubmitBatchError::Other)?;
    let versioned_hashes = verify_blobs(blobs, &block_hashes).map_err(SubmitBatchError::Other)?;
    Ok(sign_batch(batch_root, versioned_hashes, signing_key))
}

fn submit_batch_to_response(
    result: Result<SubmitBatchResponse, SubmitBatchError>,
    public_key: &[u8],
) -> EnclaveResponse {
    match result {
        Ok(r) => EnclaveResponse::SubmitBatchResult(r),
        Err(SubmitBatchError::InvalidSignatures(invalid_blocks)) => {
            EnclaveResponse::InvalidSignatures {
                invalid_blocks,
                enclave_address: pubkey_to_eth_address(public_key),
            }
        }
        Err(SubmitBatchError::Other(e)) => EnclaveResponse::Error(format!("{e:#}")),
    }
}

// ---------------------------------------------------------------------------
// Block execution — shared core
// ---------------------------------------------------------------------------

struct ExecutionResult {
    block_number: u64,
    leaf: [u8; 32],
    block_hash: B256,
}

fn run_block(
    input: EthClientExecutorInput,
    cert: Option<&CertVerifyInput>,
    block_store: &Mutex<BlockStore>,
) -> anyhow::Result<ExecutionResult> {
    let chain_spec = Arc::new(fluent_stf_primitives::fluent_chainspec());

    // Read the epoch committee from the witnessed pre-state BEFORE `execute`
    // consumes `input` (the trust anchor); `None` pre-activation / no cert. The
    // owned committee releases the witness-db borrow.
    let block_number = input.current_block.header.number;
    // Once DPoS is active a finalization cert is mandatory — refuse to attest a
    // block with no cert. Must live here (attested code), not in the proxy (untrusted).
    if cert.is_none() && fluent_stf_primitives::dpos_active(block_number) {
        return Err(anyhow::anyhow!(
            "DPoS active (block {block_number}): finalization cert required"
        ));
    }
    let committee = match cert {
        Some(_) if fluent_stf_primitives::dpos_active(block_number) => {
            let epoch = fluent_stf_primitives::epoch_of_block(
                block_number,
                fluent_stf_primitives::EPOCH_BLOCK_INTERVAL,
                fluent_stf_primitives::DPOS_ACTIVATION_BLOCK,
            );
            let snapshot = crate::dpos_committee::read_zk_committee(
                &input,
                chain_spec.clone(),
                epoch,
                fluent_stf_primitives::DPOS_STAKING_ADDRESS,
            )
            .map_err(|e| anyhow::anyhow!("DPoS committee read: {e:?}"))?;
            Some((epoch, snapshot))
        }
        _ => None,
    };

    let executor = EthClientExecutor::eth(chain_spec, input.custom_beneficiary);
    let (header, events_hash) =
        executor.execute(input).map_err(|e| anyhow::anyhow!("Block execution failed: {e:?}"))?;

    let block_hash = header.hash_slow();
    let parent_hash = header.parent_hash;
    let block_number = header.number;

    // Refuse to attest unless the executed block carries a valid quorum committee
    // finalization cert. Same blst-free core the SP1 guest runs.
    if let (Some(ci), Some((epoch, committee))) = (cert, committee.as_ref()) {
        if ci.round_epoch != *epoch {
            return Err(anyhow::anyhow!(
                "cert round epoch {} != block epoch {epoch}",
                ci.round_epoch
            ));
        }
        verify_finalization(
            committee,
            fluent_stf_primitives::FLUENT_CHAIN_ID,
            ci.round_epoch,
            ci.round_view,
            ci.parent_view,
            block_hash,
            &ci.sig_g1,
            &ci.bitmap,
        )
        .map_err(|e| anyhow::anyhow!("DPoS committee cert verify failed: {e:?}"))?;
    }

    let leaf = compute_leaf(
        parent_hash.as_slice(),
        block_hash.as_slice(),
        events_hash.withdrawal_hash.as_slice(),
        events_hash.deposit_hash.as_slice(),
    );

    block_store
        .lock()
        .map_err(|e| anyhow::anyhow!("block_store mutex poisoned: {e}"))?
        .insert(block_number, BlockEntry { leaf, block_hash });

    Ok(ExecutionResult { block_number, leaf, block_hash })
}

fn sign_execution(result: &ExecutionResult, signing_key: &SigningKey) -> EthExecutionResponse {
    let payload = execution_sign_payload(result.block_number, &result.leaf, &result.block_hash);
    let signature: Signature = signing_key.sign(&payload);

    EthExecutionResponse {
        block_number: result.block_number,
        leaf: result.leaf,
        block_hash: result.block_hash,
        signature: signature.to_bytes().into(),
    }
}

// ---------------------------------------------------------------------------
// Block execution
// ---------------------------------------------------------------------------

pub(crate) fn execute_block(
    input: EthClientExecutorInput,
    cert: Option<&CertVerifyInput>,
    signing_key: &SigningKey,
    block_store: &Mutex<BlockStore>,
) -> anyhow::Result<EthExecutionResponse> {
    let result = run_block(input, cert, block_store)?;
    Ok(sign_execution(&result, signing_key))
}

// ---------------------------------------------------------------------------
// Enclave identity & runtime
// ---------------------------------------------------------------------------

struct EnclaveIdentity {
    signing_key: SigningKey,
    public_key: Vec<u8>,
    attestation: Vec<u8>,
}

struct Enclave {
    listener: VsockListener,
}

fn send_response(channel: &mut VsockChannel, resp: &EnclaveResponse) {
    if let Err(e) = channel.send_bincode(resp) {
        eprintln!("Failed to send response to host: {e:#}");
    }
}

/// A single in-flight `ExecuteBlock` job handed off to the worker pool.
/// Owns the vsock channel so the worker can send the response when done.
struct ExecuteJob {
    channel: VsockChannel,
    input: EthClientExecutorInput,
    cert: Option<CertVerifyInput>,
    identity: Arc<EnclaveIdentity>,
    block_store: Arc<Mutex<BlockStore>>,
}

/// Spawns `n` long-lived worker threads that drain `ExecuteJob`s from a
/// bounded mpsc queue. Capacity is `n`, so at most `n` jobs can be queued
/// ahead of the workers — on saturation the accept loop will reply
/// `"enclave busy"` via `try_send` instead of blocking.
fn spawn_execute_workers(n: usize) -> SyncSender<ExecuteJob> {
    let (tx, rx) = sync_channel::<ExecuteJob>(n);
    let rx = Arc::new(Mutex::new(rx));
    for _ in 0..n {
        let rx: Arc<Mutex<Receiver<ExecuteJob>>> = Arc::clone(&rx);
        thread::spawn(move || loop {
            // Recover from poisoning — the rx mutex is only held during
            // `recv()`, so the internal state is always consistent on panic.
            let job = {
                let guard = rx.lock().unwrap_or_else(|e| e.into_inner());
                guard.recv()
            };
            let Ok(job) = job else { return };

            // Isolate `execute_block` panics: report an error to the host and
            // keep the worker alive instead of silently disappearing from the
            // pool. Without this, a single panic would shrink the pool by one
            // and eventually starve all ExecuteBlock traffic.
            let ExecuteJob { mut channel, input, cert, identity, block_store } = job;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                execute_block(input, cert.as_ref(), &identity.signing_key, &block_store)
            }));
            let resp = match result {
                Ok(Ok(output)) => EnclaveResponse::ExecutionResult(output),
                Ok(Err(e)) => EnclaveResponse::Error(format!("{e:#}")),
                Err(panic) => {
                    let msg = panic
                        .downcast_ref::<&'static str>()
                        .copied()
                        .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
                        .unwrap_or("unknown panic");
                    eprintln!("execute_block panicked: {msg}");
                    EnclaveResponse::Error(format!("execute_block panicked: {msg}"))
                }
            };
            if let Err(e) = channel.send_bincode(&resp) {
                eprintln!("Failed to send ExecuteBlock response: {e:#}");
            }
        });
    }
    tx
}

impl Enclave {
    fn init() -> anyhow::Result<Self> {
        let listener = VsockListener::bind(&VsockAddr::new(VMADDR_CID_ANY, VSOCK_PORT))
            .context("Failed to bind VSOCK listener")?;
        Ok(Self { listener })
    }

    fn run(self) -> ! {
        println!("Enclave listening, waiting for messages…");

        let mut identity: Option<Arc<EnclaveIdentity>> = None;
        let block_store = Arc::new(Mutex::new(BlockStore::new()));
        let execute_tx = spawn_execute_workers(EXECUTE_WORKER_COUNT);

        loop {
            let mut channel = match VsockChannel::accept(&self.listener) {
                Ok(ch) => ch,
                Err(e) => {
                    eprintln!("Failed to accept connection: {e:#}");
                    continue;
                }
            };

            let timeout = Some(Duration::from_secs(VSOCK_READ_TIMEOUT_SECS));
            if let Err(e) = channel.set_read_timeout(timeout) {
                eprintln!("Failed to set vsock read timeout: {e:#}");
                continue;
            }
            if let Err(e) = channel.set_write_timeout(timeout) {
                eprintln!("Failed to set vsock write timeout: {e:#}");
                continue;
            }

            let raw = match channel.receive() {
                Ok(data) => data,
                Err(e) => {
                    eprintln!("Failed to receive message: {e:#}");
                    continue;
                }
            };

            let msg: EnclaveIncoming = match bincode::deserialize(&raw) {
                Ok(m) => m,
                Err(e) => {
                    let resp = EnclaveResponse::Error(format!("Failed to deserialize: {e}"));
                    send_response(&mut channel, &resp);
                    continue;
                }
            };

            match msg {
                // ── Handshake ────────────────────────────────────
                EnclaveIncoming::Handshake { credentials } => {
                    if let Some(ref id) = identity {
                        let resp = EnclaveResponse::AlreadyInitialized {
                            public_key: id.public_key.clone(),
                            attestation: id.attestation.clone(),
                        };
                        send_response(&mut channel, &resp);
                        println!("Handshake repeated — returned existing key");
                    } else {
                        match generate_key(credentials) {
                            Ok(id) => {
                                let resp = EnclaveResponse::KeyGenerated {
                                    public_key: id.public_key.clone(),
                                    attestation: id.attestation.clone(),
                                };
                                send_response(&mut channel, &resp);
                                println!("Key generated successfully");
                                identity = Some(Arc::new(id));
                            }
                            Err(e) => {
                                let resp = EnclaveResponse::Error(format!("{e:#}"));
                                send_response(&mut channel, &resp);
                            }
                        }
                    }
                }

                // ── Phase 1: Normal block execution ──────────────
                EnclaveIncoming::ExecuteBlock { input, cert } => {
                    let Some(ref id) = identity else {
                        let resp = EnclaveResponse::NotInitialized;
                        send_response(&mut channel, &resp);
                        continue;
                    };

                    let job = ExecuteJob {
                        channel,
                        input: *input,
                        cert,
                        identity: Arc::clone(id),
                        block_store: Arc::clone(&block_store),
                    };
                    match execute_tx.try_send(job) {
                        Ok(()) => {}
                        Err(TrySendError::Full(mut j)) => {
                            let resp = EnclaveResponse::Error("enclave busy".into());
                            send_response(&mut j.channel, &resp);
                        }
                        Err(TrySendError::Disconnected(mut j)) => {
                            let resp =
                                EnclaveResponse::Error("execute worker pool disconnected".into());
                            send_response(&mut j.channel, &resp);
                        }
                    }
                }

                // ── SubmitBatch: cache-first with response fallback ──
                EnclaveIncoming::SubmitBatch { from, to, responses, blobs } => {
                    let Some(ref id) = identity else {
                        let resp = EnclaveResponse::NotInitialized;
                        send_response(&mut channel, &resp);
                        continue;
                    };

                    let resp = submit_batch_to_response(
                        handle_submit_batch(
                            from,
                            to,
                            &responses,
                            &blobs,
                            &id.signing_key,
                            &block_store,
                        ),
                        &id.public_key,
                    );
                    send_response(&mut channel, &resp);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

fn generate_key(credentials: nitro_types::AwsCredentials) -> anyhow::Result<EnclaveIdentity> {
    let kms = KmsClient::new(credentials);

    let kms_entropy = kms.generate_random().context("KMS GenerateRandom failed")?;
    let nsm_entropy = get_nsm_entropy().context("Failed to get NSM entropy")?;

    let key_bytes = derive_valid_ecdsa_key(&kms_entropy, &nsm_entropy)?;
    let signing_key = signing_key_from_bytes(&key_bytes)?;
    let public_key = encode_public_key(&signing_key);
    let attestation = create_attestation(&public_key)?;

    Ok(EnclaveIdentity { signing_key, public_key, attestation })
}

// ---------------------------------------------------------------------------
// Pure helper functions
// ---------------------------------------------------------------------------

fn signing_key_from_bytes(bytes: &[u8]) -> anyhow::Result<SigningKey> {
    let secret = SecretKey::from_bytes(bytes.into()).context("Invalid secp256k1 key bytes")?;
    Ok(SigningKey::from(secret))
}

fn encode_public_key(key: &SigningKey) -> Vec<u8> {
    key.verifying_key().to_encoded_point(false).as_bytes().to_vec()
}

/// Derive Ethereum address from uncompressed secp256k1 public key.
fn pubkey_to_eth_address(public_key: &[u8]) -> Address {
    if public_key.len() < 2 {
        return Address::ZERO;
    }
    let hash = Keccak256::digest(&public_key[1..]);
    Address::from_slice(&hash[12..32])
}

fn get_nsm_entropy() -> anyhow::Result<Vec<u8>> {
    let fd = driver::nsm_init();
    let response = driver::nsm_process_request(fd, Request::GetRandom);
    driver::nsm_exit(fd);
    match response {
        Response::GetRandom { random } => Ok(random),
        _ => Err(anyhow::anyhow!("NSM GetRandom returned unexpected response")),
    }
}

fn create_attestation(public_key: &[u8]) -> anyhow::Result<Vec<u8>> {
    let fd = driver::nsm_init();
    let response = driver::nsm_process_request(
        fd,
        Request::Attestation {
            public_key: None,
            user_data: Some(ByteBuf::from(public_key.to_vec())),
            nonce: None,
        },
    );
    driver::nsm_exit(fd);
    match response {
        Response::Attestation { document } => Ok(document),
        _ => Err(anyhow::anyhow!("NSM Attestation failed")),
    }
}

fn derive_valid_ecdsa_key(data_key: &[u8], r_local: &[u8]) -> anyhow::Result<[u8; 32]> {
    let (_, hk) = Hkdf::<Sha256>::extract(Some(r_local), data_key);
    for counter in 0..=100u32 {
        let mut candidate = [0u8; 32];
        let info = format!("enclave-signing-key-v1-{counter}");
        hk.expand(info.as_bytes(), &mut candidate)
            .map_err(|_| anyhow::anyhow!("HKDF expansion failed"))?;
        if SecretKey::from_slice(&candidate).is_ok() {
            return Ok(candidate);
        }
    }
    Err(anyhow::anyhow!("Failed to derive valid key after 100 iterations"))
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn main() -> anyhow::Result<()> {
    println!("Nitro enclave starting");
    let enclave = Enclave::init().context("Enclave initialization failed")?;
    println!("Initialization complete, entering main loop");
    enclave.run();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn keccak_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
        batch_merkle::keccak_pair(B256::from(left), B256::from(right)).0
    }

    #[test]
    fn merkle_root_single_leaf() {
        let leaf = [0xAA; 32];
        let root = calculate_merkle_root(&[leaf]).unwrap();
        assert_eq!(root, leaf);
    }

    #[test]
    fn merkle_root_two_leaves() {
        let a = [0x01; 32];
        let b = [0x02; 32];
        let root = calculate_merkle_root(&[a, b]).unwrap();
        assert_eq!(root, keccak_pair(a, b));
    }

    #[test]
    fn merkle_root_odd_leaf_duplicated() {
        let a = [0x01; 32];
        let b = [0x02; 32];
        let c = [0x03; 32];
        let root = calculate_merkle_root(&[a, b, c]).unwrap();
        let expected = keccak_pair(keccak_pair(a, b), keccak_pair(c, c));
        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_root_empty_rejected() {
        assert!(calculate_merkle_root(&[]).is_err());
    }

    #[test]
    fn compute_leaf_deterministic() {
        let p = [0x01; 32];
        let b = [0x02; 32];
        let w = [0x03; 32];
        let d = [0x04; 32];
        let l1 = compute_leaf(&p, &b, &w, &d);
        let l2 = compute_leaf(&p, &b, &w, &d);
        assert_eq!(l1, l2);
        let l3 = compute_leaf(&p, &b, &w, &[0x05; 32]);
        assert_ne!(l1, l3);
    }

    #[test]
    fn block_store_eviction() {
        let mut store = BlockStore::new();
        let dummy = BlockEntry { leaf: [0u8; 32], block_hash: B256::ZERO };
        for i in 0..(MAX_ENTRIES as u64 + 100) {
            store.insert(i, dummy);
        }
        assert_eq!(store.entries.len(), MAX_ENTRIES);
        assert!(!store.entries.contains_key(&0));
        assert!(!store.entries.contains_key(&99));
        assert!(store.entries.contains_key(&100));
    }

    #[test]
    fn handle_submit_batch_invalid_signatures() {
        let signing_key = SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
        let _verifying_key = *signing_key.verifying_key();
        let store = BlockStore::new();

        // Create one valid response (signed by our key) and one invalid (bad signature)
        let leaf = [0x01u8; 32];
        let block_hash = B256::ZERO;
        let payload = execution_sign_payload(10, &leaf, &block_hash);
        let sig: Signature = signing_key.sign(&payload);

        let valid_resp = EthExecutionResponse {
            block_number: 10,
            leaf,
            block_hash,
            signature: sig.to_bytes().into(),
        };

        let invalid_resp = EthExecutionResponse {
            block_number: 11,
            leaf,
            block_hash,
            signature: [0u8; 64], // garbage signature
        };

        let store = Mutex::new(store);
        let result =
            handle_submit_batch(10, 11, &[valid_resp, invalid_resp], &[], &signing_key, &store);

        match result {
            Err(SubmitBatchError::InvalidSignatures(blocks)) => {
                assert_eq!(blocks, vec![11]);
            }
            _ => panic!("Expected InvalidSignatures error"),
        }
    }

    #[test]
    fn handle_submit_batch_missing_block_collected() {
        let signing_key = SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
        let store = Mutex::new(BlockStore::new());

        // No responses, no store entries — all blocks should be invalid
        let result = handle_submit_batch(100, 102, &[], &[], &signing_key, &store);

        match result {
            Err(SubmitBatchError::InvalidSignatures(blocks)) => {
                assert_eq!(blocks, vec![100, 101, 102]);
            }
            _ => panic!("Expected InvalidSignatures error"),
        }
    }

    #[test]
    fn sign_batch_always_low_s() {
        // RFC6979 is deterministic per-key, so we need multiple keys × multiple
        // messages to get meaningful coverage of the (r, s) space.
        let mut rng = k256::elliptic_curve::rand_core::OsRng;
        for _ in 0..32 {
            let signing_key = SigningKey::random(&mut rng);
            for msg_idx in 0u32..32 {
                let mut batch_root = [0u8; 32];
                batch_root[..4].copy_from_slice(&msg_idx.to_be_bytes());
                let hashes = vec![B256::from([msg_idx as u8; 32])];
                let resp = sign_batch(batch_root, hashes, &signing_key);
                let sig = Signature::from_slice(&resp.signature[..64]).unwrap();
                assert!(
                    !bool::from(sig.s().is_high()),
                    "high-S signature produced for msg {msg_idx}"
                );
            }
        }
    }
}

#[cfg(test)]
mod fixture_tests {
    //! The enclave verify path (`run_block`'s post-execute step) accepts a REAL
    //! devnet finalization cert — the same fixture the SP1 guest is gated on.
    //! The committee read over witnessed state needs a live witness, so this
    //! exercises the verify half against the fixture's committee directly.
    use dpos_cert_verify::transcode_finalization;
    use dpos_cert_verify_zk::{verify_finalization, ZkCommittee, ZkValidator};
    use serde_json::Value;

    use super::B256;

    const FIXTURE: &str = include_str!("fixtures/dpos_finalization.json");

    fn hexb(s: &str) -> Vec<u8> {
        hex::decode(s.strip_prefix("0x").unwrap_or(s)).expect("hex")
    }

    fn fixture() -> (ZkCommittee, u64, B256, Vec<u8>) {
        let v: Value = serde_json::from_str(FIXTURE).expect("fixture json");
        let validators = v["committee"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| {
                let peer: [u8; 32] = hexb(m["peer_pubkey"].as_str().unwrap()).try_into().unwrap();
                let bls: [u8; 96] = hexb(m["bls_pubkey"].as_str().unwrap()).try_into().unwrap();
                ZkValidator::from_compressed(peer, &bls).expect("committee G2 pubkey")
            })
            .collect();
        let committee = ZkCommittee::new_sorted(v["epoch"].as_u64().unwrap(), validators);
        let chain_id = v["chain_id"].as_u64().unwrap();
        let digest = B256::from_slice(&hexb(v["digest"].as_str().unwrap()));
        let cert = hexb(v["certificate"].as_str().unwrap());
        (committee, chain_id, digest, cert)
    }

    #[test]
    fn nitro_verify_accepts_real_cert() {
        let (committee, chain_id, digest, cert) = fixture();
        let parts = transcode_finalization(&cert, committee.validators.len()).expect("transcode");
        verify_finalization(
            &committee,
            chain_id,
            parts.round_epoch,
            parts.round_view,
            parts.parent_view,
            digest,
            &parts.sig_g1,
            &parts.bitmap,
        )
        .expect("nitro verify path must accept the real finalization cert");
    }

    #[test]
    fn nitro_verify_rejects_tampered_cert() {
        let (committee, chain_id, digest, cert) = fixture();
        let mut parts =
            transcode_finalization(&cert, committee.validators.len()).expect("transcode");
        parts.sig_g1[10] ^= 0x01;
        assert!(
            verify_finalization(
                &committee,
                chain_id,
                parts.round_epoch,
                parts.round_view,
                parts.parent_view,
                digest,
                &parts.sig_g1,
                &parts.bitmap,
            )
            .is_err(),
            "tampered cert must be rejected by the nitro verify path"
        );
    }
}
