use std::{
    io::{Read, Write},
    sync::Arc,
};

use aws_config::BehaviorVersion;
use aws_credential_types::provider::ProvideCredentials;
use eyre::WrapErr;
use tokio::task;
use tracing::info;

use vsock::{VsockAddr, VsockStream};

use nitro_types::{AwsCredentials, EnclaveIncoming, EnclaveResponse, EthExecutionResponse};
use rsp_client_executor::io::EthClientExecutorInput;

use crate::{attestation::AttestationConfig, types::NitroConfig};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Normal block execution — enclave signs with block_hash in the payload.
pub(crate) async fn execute_block(
    input: EthClientExecutorInput,
    enclave_cfg: NitroConfig,
    att_cfg: Option<Arc<AttestationConfig>>,
) -> eyre::Result<EthExecutionResponse> {
    let msg = EnclaveIncoming::ExecuteBlock { input: Box::new(input) };
    execute_block_inner(msg, &enclave_cfg, att_cfg.as_ref()).await
}

/// Batch signing.
pub(crate) async fn submit_batch(
    from: u64,
    to: u64,
    responses: Vec<EthExecutionResponse>,
    blobs: Vec<Vec<u8>>,
    enclave_cfg: NitroConfig,
    att_cfg: Option<Arc<AttestationConfig>>,
) -> eyre::Result<EnclaveResponse> {
    let msg = EnclaveIncoming::SubmitBatch { from, to, responses, blobs };
    submit_batch_inner(msg, &enclave_cfg, att_cfg.as_ref()).await
}

// ---------------------------------------------------------------------------
// Dispatch — block execution
// ---------------------------------------------------------------------------

async fn execute_block_inner(
    msg: EnclaveIncoming,
    enclave_cfg: &NitroConfig,
    att_cfg: Option<&Arc<AttestationConfig>>,
) -> eyre::Result<EthExecutionResponse> {
    let resp = send_to_enclave(enclave_cfg.enclave_cid, enclave_cfg.enclave_port, &msg).await?;

    match resp {
        EnclaveResponse::ExecutionResult(r) => Ok(r),
        EnclaveResponse::NotInitialized => {
            info!(
                event = "enclave_handshake_required",
                "enclave not initialised — running handshake"
            );
            crate::attestation::driver::ensure_handshake(enclave_cfg, att_cfg).await?;
            let retry =
                send_to_enclave(enclave_cfg.enclave_cid, enclave_cfg.enclave_port, &msg).await?;
            match retry {
                EnclaveResponse::ExecutionResult(r) => Ok(r),
                EnclaveResponse::Error(e) => Err(eyre::eyre!("Enclave error on retry: {e}")),
                other => Err(eyre::eyre!("Unexpected response on retry: {other:?}")),
            }
        }
        EnclaveResponse::Error(e) => Err(eyre::eyre!("Enclave error: {e}")),
        other => Err(eyre::eyre!("Unexpected response: {other:?}")),
    }
}

// ---------------------------------------------------------------------------
// Dispatch — batch
// ---------------------------------------------------------------------------

async fn submit_batch_inner(
    msg: EnclaveIncoming,
    enclave_cfg: &NitroConfig,
    att_cfg: Option<&Arc<AttestationConfig>>,
) -> eyre::Result<EnclaveResponse> {
    let resp = send_to_enclave(enclave_cfg.enclave_cid, enclave_cfg.enclave_port, &msg).await?;

    match resp {
        r @ EnclaveResponse::SubmitBatchResult(_) => Ok(r),
        r @ EnclaveResponse::InvalidSignatures { .. } => Ok(r),
        EnclaveResponse::NotInitialized => {
            info!(
                event = "enclave_handshake_required",
                "enclave not initialised — running handshake"
            );
            crate::attestation::driver::ensure_handshake(enclave_cfg, att_cfg).await?;
            let retry =
                send_to_enclave(enclave_cfg.enclave_cid, enclave_cfg.enclave_port, &msg).await?;
            match retry {
                r @ EnclaveResponse::SubmitBatchResult(_) => Ok(r),
                r @ EnclaveResponse::InvalidSignatures { .. } => Ok(r),
                EnclaveResponse::Error(e) => Err(eyre::eyre!("Enclave error on retry: {e}")),
                other => Err(eyre::eyre!("Unexpected response on retry: {other:?}")),
            }
        }
        EnclaveResponse::Error(e) => Err(eyre::eyre!("Enclave error: {e}")),
        other => Err(eyre::eyre!("Unexpected response: {other:?}")),
    }
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

/// Returns `(public_key, attestation, is_new_key)`.
pub(crate) async fn handshake_with_enclave(
    config: &NitroConfig,
) -> eyre::Result<(Vec<u8>, Vec<u8>, bool)> {
    let credentials = resolve_aws_credentials().await?;
    let msg = EnclaveIncoming::Handshake { credentials };

    let resp = send_to_enclave(config.enclave_cid, config.enclave_port, &msg)
        .await
        .wrap_err("Handshake with enclave failed")?;

    match resp {
        EnclaveResponse::KeyGenerated { public_key, attestation } => {
            info!(event = "enclave_keygen", "ephemeral signing key generated by enclave");
            Ok((public_key, attestation, true))
        }
        EnclaveResponse::AlreadyInitialized { public_key, attestation } => {
            info!(
                event = "enclave_already_initialised",
                "enclave already initialised, received existing key"
            );
            Ok((public_key, attestation, false))
        }
        EnclaveResponse::Error(e) => Err(eyre::eyre!("Enclave returned error: {e}")),
        other => Err(eyre::eyre!("Unexpected handshake response: {other:?}")),
    }
}

// ---------------------------------------------------------------------------
// AWS credentials
// ---------------------------------------------------------------------------

async fn resolve_aws_credentials() -> eyre::Result<AwsCredentials> {
    let config = aws_config::defaults(BehaviorVersion::latest()).load().await;
    let provider = config
        .credentials_provider()
        .ok_or_else(|| eyre::eyre!("No AWS credentials provider available"))?;
    let creds =
        provider.provide_credentials().await.wrap_err("Failed to resolve AWS credentials")?;
    info!(event = "aws_credentials_resolved", "aws credentials resolved");
    Ok(AwsCredentials {
        access_key_id: creds.access_key_id().to_string(),
        secret_access_key: creds.secret_access_key().to_string(),
        session_token: creds.session_token().map(|s| s.to_string()).unwrap_or_default(),
    })
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// VSOCK communication
// ---------------------------------------------------------------------------

async fn send_to_enclave(
    cid: u32,
    port: u32,
    msg: &EnclaveIncoming,
) -> eyre::Result<EnclaveResponse> {
    let payload = bincode::serialize(msg)
        .map_err(|e| eyre::eyre!("Failed to serialize enclave request: {e}"))?;

    task::spawn_blocking(move || {
        let mut stream = VsockStream::connect(&VsockAddr::new(cid, port))
            .map_err(|e| eyre::eyre!("VSOCK connect {cid}:{port} failed: {e}"))?;

        write_frame(&mut stream, &payload)?;
        let resp_bytes = read_frame(&mut stream)?;
        bincode::deserialize(&resp_bytes)
            .map_err(|e| eyre::eyre!("Failed to deserialize enclave response: {e}"))
    })
    .await
    .map_err(|e| eyre::eyre!("Blocking task panicked: {e}"))?
}

fn write_frame(stream: &mut VsockStream, data: &[u8]) -> eyre::Result<()> {
    let len = data.len() as u32;
    stream.write_all(&len.to_be_bytes()).wrap_err("Failed to write length prefix")?;
    stream.write_all(data).wrap_err("Failed to write payload")?;
    stream.flush().wrap_err("Failed to flush stream")?;
    Ok(())
}

fn read_frame(stream: &mut VsockStream) -> eyre::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).wrap_err("Failed to read length prefix")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(eyre::eyre!("Response frame too large: {len} bytes (max {MAX_FRAME_SIZE})"));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).wrap_err("Failed to read payload")?;
    Ok(buf)
}
