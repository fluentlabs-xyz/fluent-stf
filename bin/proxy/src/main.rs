//! # proxy
//!
//! HTTP proxy that sits between callers and execution backends.
//!
//! ## Signing endpoints (Nitro TEE, caller provides `EthClientExecutorInput`)
//!
//! - `POST /sign-block-execution`     — execute block, return signed result (bincode)
//! - `POST /sign-batch-root`          — sign a batch root over caller-provided blobs (no L1/Beacon
//!   fetch)
//!
//! ## Challenge endpoints (orchestrator supplies `ClientInput` + blobs in the request body)
//!
//! - `POST /challenge/sp1/request`    — submit async SP1 zkVM proof request (binary body)
//! - `POST /challenge/sp1/status`     — poll for SP1 proof result
//!
//! ## Mock endpoints (testing, local SP1 execution; proxy builds `ClientInput` from L2 RPC)
//!
//! - `POST /mock/sp1/request`         — execute SP1 locally (CPU), return success/failure
//!
//! All endpoints are protected by `x-api-key` header.

mod attestation;
mod challenge;
mod db;
mod enclave;
mod types;

use crate::types::{NitroConfig, Sp1ProofResponse};
use nitro_types::{
    ChallengeSp1Request, EnclaveResponse, EthExecutionResponse, InvalidSignaturesResponse,
    SignBatchRootRequest,
};

use std::{env, sync::Arc};
use tokio::sync::OnceCell;

/// Lazily-initialized SP1 prover state.
/// The background init task populates this; handlers await it on first use.
type LazySp1 = Arc<OnceCell<Sp1State>>;

use alloy_primitives::Address;
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json},
    routing::post,
    Router,
};
use fluent_stf_primitives::fluent_chainspec;
use revm_primitives::{hex, B256};
use url::Url;

use serde::{Deserialize, Serialize};

use alloy_provider::{Provider, RootProvider};
use reth_chainspec::ChainSpec;
use rsp_client_executor::{evm::FluentEvmConfig, io::EthClientExecutorInput};
use rsp_host_executor::{create_eth_block_execution_strategy_factory, HostExecutor};
use rsp_provider::create_provider;

use sp1_sdk::{
    network::{prover::NetworkProver, NetworkMode},
    Elf, HashableKey, Prover, ProverClient, ProvingKey, SP1ProvingKey, SP1Stdin,
};

use rsp_blob_builder::prepare_blob_verification_input;
use tracing::{info, warn, Instrument};

pub fn rpc_url() -> String {
    if let Ok(url) = env::var("RPC_URL") {
        return url;
    }

    #[cfg(feature = "testnet")]
    return "https://rpc.testnet.fluent.xyz".to_string();

    #[cfg(feature = "devnet")]
    return "https://rpc.devnet.fluent.xyz".to_string();

    #[allow(unreachable_code)]
    "http://localhost:8545".to_string()
}

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct AppState {
    api_key: String,
    nitro: NitroConfig,
    att_cfg: Option<Arc<attestation::AttestationConfig>>,
    sp1: Option<LazySp1>,
    /// Raw SP1 ELF bytes for local CPU execution via the mock endpoint.
    sp1_elf_bytes: Option<Arc<Vec<u8>>>,
    /// RPC / chain context for `ClientInput` construction on the mock
    /// endpoint. Not used by `/challenge/sp1/request` — the orchestrator
    /// supplies a fully-built `ClientInput` in the request body.
    chain: ChainContext,
    /// L1 context for batch-range lookup on the `/mock/sp1/request` path.
    /// Not used by `/challenge/sp1/request` — the orchestrator supplies
    /// pre-built blobs in the request body.
    l1: Option<L1State>,
}

#[derive(Clone)]
struct L1State {
    /// L1 RPC provider (rollup contract reads).
    l1_provider: RootProvider,
    /// Rollup contract address on L1.
    contract_addr: Address,
    /// L1 block where the rollup contract was deployed (lower bound for log scans).
    deploy_block: u64,
}

#[derive(Clone)]
struct Sp1State {
    client: Arc<NetworkProver>,
    pk: Arc<SP1ProvingKey>,
}

#[derive(Clone)]
struct ChainContext {
    block_execution_strategy_factory: FluentEvmConfig,
    chain_spec: Arc<ChainSpec>,
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// `POST /mock/sp1/request` — block ref + batch index for blob fetching.
#[derive(Deserialize)]
struct MockSp1Request {
    block_number: Option<u64>,
    block_hash: Option<B256>,
    batch_index: u64,
}

#[derive(Deserialize)]
struct Sp1StatusRequest {
    request_id: B256,
}

#[derive(Serialize)]
struct Sp1RequestResponse {
    request_id: B256,
}

#[derive(Serialize)]
struct MockSp1Response {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

type HandlerError = (StatusCode, Json<ErrorResponse>);

fn bad_request(msg: impl ToString) -> HandlerError {
    (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: msg.to_string() }))
}

fn internal(msg: impl ToString) -> HandlerError {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: msg.to_string() }))
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

async fn require_api_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> impl IntoResponse {
    let provided = headers.get("x-api-key").and_then(|v| v.to_str().ok()).unwrap_or("");

    if provided != state.api_key {
        warn!(event = "auth_rejected", "auth rejected — invalid or missing x-api-key");
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse { error: "Invalid or missing x-api-key".into() }),
        )
            .into_response();
    }

    next.run(request).await
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn require_sp1(state: &AppState) -> Result<&Sp1State, HandlerError> {
    match &state.sp1 {
        None => Err(internal("SP1 prover not configured (set SP1_ELF_PATH)")),
        Some(cell) => {
            cell.get().ok_or_else(|| internal("SP1 prover still initializing, please retry"))
        }
    }
}

fn require_l1(state: &AppState) -> Result<&L1State, HandlerError> {
    state.l1.as_ref().ok_or_else(|| internal("L1 not configured (set L1_RPC_URL, L1_ROLLUP_ADDR)"))
}

/// Generates KZG commitments and proofs on the host using Fiat-Shamir.
/// This witness is sent to SP1 to avoid heavy MSMs inside the zkVM.
/// Fetch blobs for a challenge endpoint by reconstructing them from L2 tx data.
///
/// Resolves the batch's L2 block range via an L1 `acceptNextBatch` calldata
/// lookup, then rebuilds the canonical blobs from L2 RPC — no Beacon API.
async fn fetch_challenge_blobs(
    l1: &L1State,
    batch_index: u64,
) -> Result<Vec<Vec<u8>>, HandlerError> {
    let l2_url = Url::parse(&rpc_url()).map_err(|e| internal(format!("Invalid rpc_url: {e}")))?;
    let l2_provider: RootProvider = create_provider(l2_url)
        .map_err(|e| internal(format!("Failed to build L2 provider: {e}")))?;

    let (from_block, to_block) = l1_rollup_client::fetch_batch_range(
        &l1.l1_provider,
        &l2_provider,
        l1.contract_addr,
        batch_index,
        l1.deploy_block,
    )
    .await
    .map_err(|e| internal(format!("Batch range lookup failed: {e}")))?;

    rsp_blob_builder::build_blobs_from_l2(&l2_provider, from_block, to_block)
        .await
        .map_err(|e| internal(format!("Blob construction failed: {e}")))
}

/// Resolves a block number from either `block_number` or `block_hash`,
/// fetches the block from RPC and runs host-side execution to produce
/// an `EthClientExecutorInput`.
async fn build_client_input(
    block_number: Option<u64>,
    block_hash: Option<B256>,
    chain: &ChainContext,
) -> Result<EthClientExecutorInput, HandlerError> {
    let url = Url::parse(&rpc_url()).map_err(|e| bad_request(format!("Invalid rpc_url: {e}")))?;
    let provider: RootProvider =
        create_provider(url).map_err(|e| internal(format!("Failed to build provider: {e}")))?;

    let block_number = match (block_number, block_hash) {
        (_, Some(hash)) => {
            provider
                .get_block_by_hash(hash)
                .await
                .map_err(|e| internal(format!("RPC error: {e}")))?
                .ok_or_else(|| bad_request(format!("Block not found for hash: {hash}")))?
                .header
                .number
        }
        (Some(number), _) => number,
        (None, None) => {
            return Err(bad_request("Either block_number or block_hash must be provided"))
        }
    };

    let host_executor =
        HostExecutor::new(chain.block_execution_strategy_factory.clone(), chain.chain_spec.clone());

    host_executor
        .execute(block_number, &provider, None, false)
        .await
        .map_err(|e| internal(format!("Block execution failed: {e}")))
}

// ===========================================================================
// Signing endpoints — caller provides EthClientExecutorInput
// ===========================================================================

/// `POST /sign-block-execution`
///
/// Body: bincode-serialized `SignBlockExecutionBody` (the `{input_payload, cert}`
/// wrapper — `input_payload` is itself a bincode'd `EthClientExecutorInput`),
/// optionally zstd-compressed (indicated by `Content-Encoding: zstd`).
/// Headers: `Content-Type: application/octet-stream`.
#[tracing::instrument(skip_all, fields(block_number = tracing::field::Empty))]
async fn sign_block_execution(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<EthExecutionResponse>, HandlerError> {
    let body = maybe_decompress(&headers, &body)?;
    let wrapper = decode_bincode::<nitro_types::SignBlockExecutionBody>(&body)?;
    let input = decode_bincode::<EthClientExecutorInput>(&wrapper.input_payload)?;
    let cert = wrapper.cert;
    let block_number = input.current_block.header.number;
    tracing::Span::current().record("block_number", block_number);
    info!(event = "sign_block_execution_received", "sign-block-execution request received");

    // The finalization cert rides in the wrapper (the orchestrator sources it
    // from `consensus_getFinalization`); empty pre-activation, in which case the
    // enclave's committee verify stays gated off by the activation block.
    let response = enclave::execute_block(input, cert, state.nitro, state.att_cfg.clone())
        .await
        .map_err(|e| internal(format!("Enclave execution failed: {e}")))?;

    Ok(Json(response))
}

/// If the request has `Content-Encoding: zstd`, decompress; otherwise return
/// the body as-is (borrowed). Rejects unknown encodings to fail loudly instead
/// of feeding compressed bytes to bincode.
fn maybe_decompress<'a>(
    headers: &HeaderMap,
    body: &'a [u8],
) -> Result<std::borrow::Cow<'a, [u8]>, HandlerError> {
    let Some(encoding) = headers.get("content-encoding") else {
        return Ok(std::borrow::Cow::Borrowed(body));
    };
    let encoding = encoding
        .to_str()
        .map_err(|e| bad_request(format!("Invalid content-encoding header: {e}")))?;
    match encoding {
        "zstd" => {
            let decompressed = zstd::decode_all(body)
                .map_err(|e| bad_request(format!("zstd decompression failed: {e}")))?;
            Ok(std::borrow::Cow::Owned(decompressed))
        }
        other => Err(bad_request(format!("Unsupported content-encoding: {other}"))),
    }
}

/// Decode a bincode payload.
fn decode_bincode<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, HandlerError> {
    bincode::deserialize(body)
        .map_err(|e| bad_request(format!("Bincode deserialization failed: {e}")))
}

/// `POST /sign-batch-root`
///
/// Caller (witness-orchestrator) passes pre-built EIP-4844 blobs reconstructed
/// from L2 transaction data; the proxy forwards them to the enclave for
/// signing. No L1 / Beacon API access on this path.
#[tracing::instrument(skip_all, fields(from_block = req.from_block, to_block = req.to_block, num_blobs = req.blobs.len()))]
async fn sign_batch_root(
    State(state): State<AppState>,
    Json(req): Json<SignBatchRootRequest>,
) -> Result<impl IntoResponse, HandlerError> {
    if req.from_block > req.to_block {
        return Err(bad_request(format!(
            "invalid range: from_block ({}) > to_block ({})",
            req.from_block, req.to_block
        )));
    }

    if req.blobs.is_empty() {
        return Err(bad_request("blobs field is required and must not be empty"));
    }

    info!(event = "sign_batch_root_received", "sign-batch-root request received");

    // Blobs are now provided by the courier — no L1/Beacon fetch needed
    let outcome = enclave::submit_batch(
        req.from_block,
        req.to_block,
        req.responses,
        req.blobs,
        state.nitro,
        state.att_cfg.clone(),
    )
    .await
    .map_err(|e| internal(format!("Batch submission failed: {e}")))?;

    match outcome {
        EnclaveResponse::SubmitBatchResult(resp) => Ok(Json(resp).into_response()),
        EnclaveResponse::InvalidSignatures { invalid_blocks, enclave_address } => Ok((
            StatusCode::CONFLICT,
            Json(InvalidSignaturesResponse { invalid_blocks, enclave_address }),
        )
            .into_response()),
        other => Err(internal(format!("Unexpected enclave response: {other:?}"))),
    }
}

// ===========================================================================
// Challenge endpoints — orchestrator supplies ClientInput + blobs
// ===========================================================================

/// `POST /challenge/sp1/request`
///
/// Body: bincode-serialized [`nitro_types::ChallengeSp1Request`] —
/// `{ client_input: EthClientExecutorInput, blobs: Vec<Vec<u8>> }` —
/// optionally zstd-compressed (indicated by `Content-Encoding: zstd`).
/// Headers: `Content-Type: application/octet-stream`.
///
/// The orchestrator owns the witness payload (via its embedded driver's
/// cold-store / MDBX rebuild) and the canonical batch blobs (via
/// `rsp_blob_builder::build_blobs_from_l2`). The proxy is a thin SP1
/// forwarder on this path: no L1 / Beacon access, no host-execute, no
/// witness-hub lookup.
#[tracing::instrument(
    skip_all,
    fields(
        block_number = tracing::field::Empty,
        request_id = tracing::field::Empty,
    ),
)]
async fn challenge_sp1_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Sp1RequestResponse>, HandlerError> {
    let sp1 = require_sp1(&state).await?;

    let body = maybe_decompress(&headers, &body)?;
    let payload = decode_bincode::<ChallengeSp1Request>(&body)?;
    let client_input = *payload.client_input;
    let raw_blobs = payload.blobs;

    let block_number = client_input.current_block.header.number;
    let blob_input =
        prepare_blob_verification_input(&raw_blobs).map_err(|e| internal(format!("KZG: {e}")))?;

    let mut stdin = SP1Stdin::new();
    let serialized_input = bincode::serialize(&client_input)
        .map_err(|e| internal(format!("Failed to serialize client input: {e}")))?;
    stdin.write_slice(&serialized_input);

    let serialized_blobs = bincode::serialize(&blob_input)
        .map_err(|e| internal(format!("Failed to serialize blob input: {e}")))?;
    stdin.write_slice(&serialized_blobs);

    let challenge_id = B256::random();
    let request_id_hex = hex::encode(challenge_id);
    tracing::Span::current().record("block_number", block_number);
    tracing::Span::current().record("request_id", request_id_hex.as_str());

    if let Some(db) = db::db() {
        db.create_challenge(challenge_id, block_number);
    }

    info!(
        event = "challenge_proof_accepted",
        num_blobs = raw_blobs.len(),
        "challenge proof accepted, starting background retry loop",
    );

    let client = sp1.client.clone();
    let pk = sp1.pk.clone();
    tokio::spawn(
        challenge::run_challenge_proof(client, pk, stdin, challenge_id, block_number)
            .in_current_span(),
    );

    Ok(Json(Sp1RequestResponse { request_id: challenge_id }))
}

/// `POST /challenge/sp1/status`
/// Body: `{ request_id }`
/// Returns: `Sp1ProofResponse` (200) | 202 Accepted (pending) | 404 (not found)
#[tracing::instrument(skip_all, fields(request_id = %hex::encode(req.request_id)))]
async fn challenge_sp1_status(Json(req): Json<Sp1StatusRequest>) -> impl IntoResponse {
    let challenge_id = req.request_id;

    let row = match db::db().and_then(|db| db.get_challenge(challenge_id)) {
        Some(r) => r,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("Challenge not found: {}", hex::encode(challenge_id)),
                }),
            )
                .into_response();
        }
    };

    match row.status.as_str() {
        "completed" => {
            let proof_bytes = row.proof_bytes.unwrap_or_default();
            info!(event = "challenge_proof_ready", "challenge proof ready");
            (StatusCode::OK, Json(Sp1ProofResponse { proof_bytes })).into_response()
        }
        "failed" => {
            let error = row.error.unwrap_or_else(|| "Unknown error".into());
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error })).into_response()
        }
        _ => {
            info!(event = "challenge_proof_pending", "challenge proof pending");
            StatusCode::ACCEPTED.into_response()
        }
    }
}

/// Resume in-flight SP1 challenge proofs after a proxy restart.
///
/// Called from the SP1 init background task as soon as `Sp1State` is
/// available. Mirrors the attestation `resume_all_pending` pattern: rows
/// with a stored `sp1_request_id` get a worker that calls
/// `wait_proof(saved_id, ...)` (no stdin reconstruction needed); rows
/// without an ID are marked failed so the orchestrator's existing 5xx →
/// re-issue path generates a fresh request.
async fn resume_all_pending_challenges(sp1_state: &Sp1State) {
    let rows = {
        let Some(db) = crate::db::db() else { return };
        db.load_pending_challenges()
    };
    if rows.is_empty() {
        info!(event = "challenge_resume_none", "no pending challenges to resume");
        return;
    }
    info!(event = "challenge_resume_started", count = rows.len(), "resuming pending challenges");
    for row in rows {
        match row.sp1_request_id {
            Some(sp1_id) => {
                let client = sp1_state.client.clone();
                let request_id_hex = hex::encode(row.challenge_id);
                tokio::spawn(
                    challenge::resume_challenge_proof(client, row.challenge_id, sp1_id).instrument(
                        tracing::info_span!(
                            "challenge_resume_worker",
                            worker = "challenge_resume",
                            request_id = %request_id_hex,
                        ),
                    ),
                );
            }
            None => {
                if let Some(db) = crate::db::db() {
                    db.set_challenge_failed(
                        row.challenge_id,
                        "proxy restart before SP1 submit — orchestrator must re-issue",
                    );
                }
            }
        }
    }
}

// ===========================================================================
// Mock endpoints
// ===========================================================================

/// `POST /mock/sp1/request` — local SP1 zkVM execution, no network call.
///
/// Self-contained dev/testing endpoint: the proxy builds `ClientInput`
/// from L2 RPC and reconstructs blobs from L2 tx data via blob-builder.
/// Body: `{ block_number?, block_hash?, batch_index }`. Returns
/// `{ success, error? }`.
#[tracing::instrument(skip_all, fields(batch_index = req.batch_index, block_number = tracing::field::Empty))]
async fn mock_sp1_request(
    State(state): State<AppState>,
    Json(req): Json<MockSp1Request>,
) -> Result<Json<MockSp1Response>, HandlerError> {
    let elf_bytes = state
        .sp1_elf_bytes
        .as_ref()
        .ok_or_else(|| internal("SP1 ELF not configured (set SP1_ELF_PATH)"))?
        .clone();

    let l1 = require_l1(&state)?;

    info!(
        event = "mock_sp1_received",
        requested_block_number = ?req.block_number,
        requested_block_hash = ?req.block_hash,
        "mock sp1 execution received",
    );

    let raw_blobs = fetch_challenge_blobs(l1, req.batch_index).await?;
    let client_input = build_client_input(req.block_number, req.block_hash, &state.chain).await?;
    let block_number = client_input.current_block.header.number;
    tracing::Span::current().record("block_number", block_number);
    let blob_input =
        prepare_blob_verification_input(&raw_blobs).map_err(|e| internal(format!("KZG: {e}")))?;

    let mut stdin = SP1Stdin::new();
    let serialized_input = bincode::serialize(&client_input)
        .map_err(|e| internal(format!("Failed to serialize client input: {e}")))?;
    stdin.write_slice(&serialized_input);
    let serialized_blobs = bincode::serialize(&blob_input)
        .map_err(|e| internal(format!("Failed to serialize blob input: {e}")))?;
    stdin.write_slice(&serialized_blobs);

    info!(event = "mock_sp1_executing", "executing sp1 program locally (cpu)");

    let handle = tokio::runtime::Handle::current();
    let result = tokio::task::spawn_blocking(move || {
        handle.block_on(async {
            let client = sp1_sdk::ProverClient::builder().cpu().build().await;
            client.execute(Elf::from(elf_bytes.as_ref().clone()), stdin).await
        })
    })
    .await
    .map_err(|e| internal(format!("SP1 execution task panicked: {e}")))?;

    match result {
        Ok((_public_values, report)) => {
            info!(
                event = "mock_sp1_done",
                total_instructions = report.total_instruction_count(),
                "mock sp1 execution succeeded",
            );
            Ok(Json(MockSp1Response { success: true, error: None }))
        }
        Err(e) => {
            warn!(event = "mock_sp1_failed", err = %e, "mock sp1 execution failed");
            Ok(Json(MockSp1Response { success: false, error: Some(format!("{e}")) }))
        }
    }
}

// ---------------------------------------------------------------------------
// Entry-point
// ---------------------------------------------------------------------------

/// Default `EnvFilter` directives. Trims noisy external crates to `warn` so
/// production logs are not drowned by RPC retry / connection-pool / vsock
/// chatter. `RUST_LOG`, when set, replaces this list verbatim; last directive
/// wins, so operators can re-enable any crate (e.g. `RUST_LOG=info,alloy=debug`).
const DEFAULT_TRACING_DIRECTIVES: &str = "info,\
    alloy=warn,\
    reth=warn,\
    hyper=warn,\
    hyper_util=warn,\
    reqwest=warn,\
    tower=warn,\
    h2=warn";

fn init_tracing() {
    use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(DEFAULT_TRACING_DIRECTIVES));

    let format = std::env::var("LOG_FORMAT").unwrap_or_else(|_| "pretty".into());
    let deploy_env = std::env::var("DEPLOY_ENV").unwrap_or_else(|_| "unknown".into());

    match format.as_str() {
        "json" => {
            let layer = tracing_format::json_layer("proxy", env!("CARGO_PKG_VERSION"), deploy_env);
            tracing_subscriber::registry().with(env_filter).with(layer).init();
        }
        _ => {
            tracing_subscriber::registry().with(env_filter).with(fmt::layer()).init();
        }
    }
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    init_tracing();

    let db_path = std::env::var("PROXY_DB_PATH").unwrap_or_else(|_| "./proxy.db".into());
    db::init(&db_path)?;

    // ── SP1 prover (lazy init) ────────────────────────────────────────────
    let mut sp1_elf_bytes: Option<Arc<Vec<u8>>> = None;
    let sp1: Option<LazySp1> = match std::env::var("SP1_ELF_PATH") {
        Err(_) => {
            info!(
                event = "sp1_disabled",
                "sp1_elf_path not set — /challenge/sp1 endpoints disabled"
            );
            None
        }
        Ok(elf_path) => {
            let elf_bytes = std::fs::read(&elf_path)
                .map_err(|e| eyre::eyre!("Failed to read SP1 ELF {elf_path}: {e}"))?;

            sp1_elf_bytes = Some(Arc::new(elf_bytes.clone()));

            let cell = Arc::new(OnceCell::new());
            let cell_clone = cell.clone();

            tokio::spawn(
                async move {
                    let elf = Elf::from(elf_bytes);
                    let client =
                        ProverClient::builder().network_for(NetworkMode::Mainnet).build().await;
                    let pk = client.setup(elf).await.unwrap();
                    let vk = pk.verifying_key();
                    info!(
                        event = "sp1_prover_initialised",
                        vk_hash = %vk.bytes32(),
                        "sp1 prover initialised (background)",
                    );
                    let state = Sp1State { client: Arc::new(client), pk: Arc::new(pk) };
                    let _ = cell_clone.set(state.clone());
                    // Now that SP1 is ready, resume any in-flight challenge
                    // proofs whose `tokio::spawn` worker did not survive the
                    // process restart.
                    resume_all_pending_challenges(&state).await;
                }
                .instrument(tracing::info_span!("sp1_init", worker = "sp1_init")),
            );

            info!(event = "sp1_init_started", "sp1 prover initialization started in background");
            Some(cell)
        }
    };

    // ── Chain context (for challenge endpoints) ──────────────────────────
    let block_execution_strategy_factory = create_eth_block_execution_strategy_factory(None);
    let chain_spec: Arc<ChainSpec> = Arc::new(fluent_chainspec());

    let chain = ChainContext { block_execution_strategy_factory, chain_spec };

    // ── L1 context (for batch metadata lookup in challenge endpoints) ────
    let l1 = match (env::var("L1_RPC_URL"), env::var("L1_ROLLUP_ADDR")) {
        (Ok(l1_rpc), Ok(l1_addr)) => {
            let l1_url = Url::parse(&l1_rpc).map_err(|e| eyre::eyre!("Invalid L1_RPC_URL: {e}"))?;
            let l1_provider: RootProvider = create_provider(l1_url)?;
            let contract_addr: Address =
                l1_addr.parse().map_err(|e| eyre::eyre!("Invalid L1_ROLLUP_ADDR: {e}"))?;
            let deploy_block: u64 =
                env::var("L1_ROLLUP_DEPLOY_BLOCK").ok().and_then(|s| s.parse().ok()).unwrap_or(0);

            info!(
                event = "l1_context_initialized",
                l1_rpc = %l1_rpc,
                contract_addr = %l1_addr,
                deploy_block,
                "l1 context initialized for batch metadata lookup",
            );

            Some(L1State { l1_provider, contract_addr, deploy_block })
        }
        _ => {
            info!(
                event = "l1_disabled",
                "l1_rpc_url/l1_rollup_addr not set — challenge endpoints disabled"
            );
            None
        }
    };

    let nitro = NitroConfig::default();

    let att_cfg: Option<Arc<attestation::AttestationConfig>> =
        match attestation::AttestationConfig::from_env().await {
            Ok(cfg) => {
                info!(event = "attestation_config_initialised", "attestation config initialised");
                Some(Arc::new(cfg))
            }
            Err(e) => {
                warn!(
                    event = "attestation_config_unavailable",
                    err = %e,
                    "attestation config unavailable — running without attestation proving",
                );
                None
            }
        };

    attestation::driver::resume_all_pending(att_cfg.as_ref()).await;

    attestation::driver::ensure_handshake(&nitro, att_cfg.as_ref()).await?;
    info!(event = "enclave_handshake_complete", "nitro enclave handshake complete");

    let api_key = std::env::var("API_KEY")?;
    let listen_addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());

    let state = AppState { api_key, nitro, att_cfg, sp1, sp1_elf_bytes, chain, l1 };

    let app = Router::new()
        // ── Signing (TEE, input from caller) ─────────────
        .route("/sign-block-execution", post(sign_block_execution))
        .route("/sign-batch-root", post(sign_batch_root))
        // ── Challenge (orchestrator supplies ClientInput + blobs in body) ──
        .route("/challenge/sp1/request", post(challenge_sp1_request))
        .route("/challenge/sp1/status", post(challenge_sp1_status))
        // ── Mock (testing — proxy builds from L2 RPC) ─────
        .route("/mock/sp1/request", post(mock_sp1_request))
        .layer(DefaultBodyLimit::max(usize::MAX))
        // ── Auth ─────────────────────────────────────────
        .route_layer(middleware::from_fn_with_state(state.clone(), require_api_key))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    info!(event = "proxy_listening", listen_addr = %listen_addr, "proxy listening");
    axum::serve(listener, app).await?;

    Ok(())
}
