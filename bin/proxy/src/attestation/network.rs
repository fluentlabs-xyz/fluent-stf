use std::{collections::HashSet, sync::Arc, time::Duration};

use alloy_network::EthereumWallet;
use alloy_primitives::Address;
use alloy_provider::{ProviderBuilder, RootProvider};
use alloy_signer_local::PrivateKeySigner;
use eyre::{eyre, Result};
use l1_rollup_client::nitro_verifier;
use revm_primitives::{hex, B256};
use sp1_sdk::{
    network::{
        proto::auction::{
            network::prover_network_client::ProverNetworkClient, types::GetProversByUptimeRequest,
        },
        prover::NetworkProver,
        utils::get_default_rpc_url_for_mode,
        Error as Sp1NetworkError, NetworkMode,
    },
    Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1ProvingKey, SP1Stdin,
};
use tonic::transport::Endpoint;
use tracing::{info, warn};
use url::Url;

use super::{prepare, ROOT_CERT_DER};

/// Configuration for attestation proving + L1 submission.
#[derive(Clone)]
pub(crate) struct AttestationConfig {
    pub prover: Arc<NetworkProver>,
    pub pk: Arc<SP1ProvingKey>,
    pub l1_provider: RootProvider,
    pub l1_signer: PrivateKeySigner,
    pub nitro_verifier_addr: Address,
}

impl AttestationConfig {
    pub(crate) async fn from_env() -> Result<Self> {
        let elf_path = std::env::var("NITRO_VALIDATOR_ELF_PATH")
            .map_err(|_| eyre!("NITRO_VALIDATOR_ELF_PATH not set"))?;
        let elf_bytes = std::fs::read(&elf_path)
            .map_err(|e| eyre!("Failed to read nitro validator ELF {elf_path}: {e}"))?;
        let elf = Elf::from(elf_bytes);

        let client = ProverClient::builder().network_for(NetworkMode::Mainnet).build().await;
        let pk = client
            .setup(elf)
            .await
            .map_err(|e| eyre!("Failed to setup nitro validator proving key: {e}"))?;

        info!(
            event = "nitro_validator_sp1_initialised",
            vk_hash = %pk.verifying_key().bytes32(),
            "nitro validator sp1 prover initialised",
        );

        let l1_rpc = std::env::var("L1_RPC_URL").map_err(|_| eyre!("L1_RPC_URL not set"))?;
        let l1_url = Url::parse(&l1_rpc)?;
        let l1_provider: RootProvider = rsp_provider::create_provider(l1_url)?;

        let key_hex =
            std::env::var("L1_SUBMITTER_KEY").map_err(|_| eyre!("L1_SUBMITTER_KEY not set"))?;
        let l1_signer: PrivateKeySigner =
            key_hex.parse().map_err(|e| eyre!("Invalid L1_SUBMITTER_KEY: {e}"))?;

        Ok(Self {
            prover: Arc::new(client),
            pk: Arc::new(pk),
            l1_provider,
            l1_signer,
            nitro_verifier_addr: fluent_stf_primitives::NITRO_VERIFIER_ADDR,
        })
    }
}

// ---------------------------------------------------------------------------
// Proving flow
// ---------------------------------------------------------------------------

/// Submit attestation proof for a specific enclave key.
///
/// - If a `request_id` is already saved for this key, try `wait_proof` on it first.
/// - Otherwise submit a fresh SP1 request with HA whitelist + unfulfillable retry.
/// - On success: submit Groth16 proof to L1 NitroVerifier, delete the DB row.
/// - Errors propagate; the caller (driver's `run_prove_loop`) applies outer retry.
pub(crate) async fn prove_and_submit_for_key(
    config: &AttestationConfig,
    public_key: &[u8],
    attestation: &[u8],
) -> Result<()> {
    let saved_id = crate::db::db().and_then(|db| db.get_request_id(public_key));

    if let Some(id) = saved_id {
        info!(event = "attestation_resume_starting", sp1_request_id = %hex::encode(id), "resuming pending attestation proof");
        match config.prover.wait_proof(id, None, None).await {
            Ok(proof) => {
                submit_proof_to_l1(config, public_key, &proof).await?;
                if let Some(db) = crate::db::db() {
                    db.delete_pending_attestation(public_key);
                }
                return Ok(());
            }
            Err(e) => {
                warn!(event = "attestation_resume_failed", err = %e, "failed to resume saved proof — will submit fresh request");
                if let Some(db) = crate::db::db() {
                    db.clear_request_id(public_key);
                }
            }
        }
    }

    let guest_input = prepare::prepare_guest_input(attestation, ROOT_CERT_DER)
        .map_err(|e| eyre!("Failed to prepare guest input: {e}"))?;

    let mut stdin = SP1Stdin::new();
    stdin.write(&guest_input);

    let mut blacklist: HashSet<Address> = HashSet::new();

    loop {
        let whitelist = fetch_ha_whitelist(&blacklist).await?;

        info!(
            event = "attestation_request_submitting",
            whitelist_size = whitelist.len(),
            blacklist_size = blacklist.len(),
            "submitting attestation proof to sp1 network",
        );

        let id = config
            .prover
            .prove(config.pk.as_ref(), stdin.clone())
            .groth16()
            .whitelist(Some(whitelist))
            .request()
            .await
            .map_err(|e| eyre!("SP1 attestation proof request failed: {e}"))?;

        if let Some(db) = crate::db::db() {
            db.set_request_id(public_key, id);
        }
        info!(event = "attestation_request_submitted", sp1_request_id = %hex::encode(id), "attestation proof submitted");

        match config.prover.wait_proof(id, None, None).await {
            Ok(proof) => {
                submit_proof_to_l1(config, public_key, &proof).await?;
                if let Some(db) = crate::db::db() {
                    db.delete_pending_attestation(public_key);
                }
                return Ok(());
            }
            Err(e) => {
                let is_retriable = e.downcast_ref::<Sp1NetworkError>().is_some_and(|ne| {
                    matches!(
                        ne,
                        Sp1NetworkError::RequestUnfulfillable { .. } |
                            Sp1NetworkError::RequestUnexecutable { .. } |
                            Sp1NetworkError::RequestTimedOut { .. } |
                            Sp1NetworkError::RequestAuctionTimedOut { .. }
                    )
                });

                if !is_retriable {
                    if let Some(db) = crate::db::db() {
                        db.clear_request_id(public_key);
                    }
                    return Err(eyre!("SP1 attestation proof failed: {e}"));
                }

                if let Some(fulfiller) = identify_fulfiller(&config.prover, id).await {
                    warn!(
                        event = "attestation_prover_unfulfillable",
                        sp1_request_id = %hex::encode(id),
                        fulfiller = %fulfiller,
                        err = %e,
                        "attestation proof request failed (retriable) — blacklisting fulfiller",
                    );
                    blacklist.insert(fulfiller);
                } else {
                    warn!(
                        event = "attestation_prover_unfulfillable_unknown",
                        sp1_request_id = %hex::encode(id),
                        err = %e,
                        "attestation proof request failed (retriable) — could not identify fulfiller",
                    );
                }

                if let Some(db) = crate::db::db() {
                    db.clear_request_id(public_key);
                }

                let ha_count = fetch_ha_prover_count().await.unwrap_or(0);
                if ha_count > 0 && blacklist.len() >= ha_count {
                    warn!(
                        event = "ha_blacklist_reset",
                        blacklist_size = blacklist.len(),
                        "all ha provers blacklisted — resetting blacklist"
                    );
                    blacklist.clear();
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// HA prover helpers
// ---------------------------------------------------------------------------

/// Fetch high-availability provers from SP1 network, filtering out blacklisted addresses.
pub(crate) async fn fetch_ha_whitelist(blacklist: &HashSet<Address>) -> Result<Vec<Address>> {
    let rpc_url = get_default_rpc_url_for_mode(NetworkMode::Mainnet);
    let channel = Endpoint::new(rpc_url)?
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(15))
        .connect()
        .await
        .map_err(|e| eyre!("Failed to connect to SP1 network: {e}"))?;

    let mut client = ProverNetworkClient::new(channel);
    let response = client
        .get_provers_by_uptime(GetProversByUptimeRequest { high_availability_only: false })
        .await
        .map_err(|e| eyre!("Failed to fetch HA provers: {e}"))?;

    let provers: Vec<Address> = response
        .into_inner()
        .provers
        .into_iter()
        .map(|p| Address::from_slice(&p))
        .filter(|addr| !blacklist.contains(addr))
        .collect();

    if provers.is_empty() {
        return Err(eyre!("No available HA provers after filtering blacklist"));
    }

    Ok(provers)
}

/// Fetch total count of HA provers (unfiltered).
pub(crate) async fn fetch_ha_prover_count() -> Result<usize> {
    let rpc_url = get_default_rpc_url_for_mode(NetworkMode::Mainnet);
    let channel = Endpoint::new(rpc_url)?
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(15))
        .connect()
        .await
        .map_err(|e| eyre!("Failed to connect to SP1 network: {e}"))?;

    let mut client = ProverNetworkClient::new(channel);
    let response = client
        .get_provers_by_uptime(GetProversByUptimeRequest { high_availability_only: true })
        .await
        .map_err(|e| eyre!("Failed to fetch HA provers: {e}"))?;

    Ok(response.into_inner().provers.len())
}

/// Query SP1 network for the fulfiller address of a proof request.
pub(crate) async fn identify_fulfiller(
    prover: &NetworkProver,
    request_id: B256,
) -> Option<Address> {
    let request = prover.get_proof_request(request_id).await.ok()??;
    let fulfiller_bytes = request.fulfiller?;
    if fulfiller_bytes.len() == 20 {
        Some(Address::from_slice(&fulfiller_bytes))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// L1 submission
// ---------------------------------------------------------------------------

async fn submit_proof_to_l1(
    config: &AttestationConfig,
    public_key: &[u8],
    proof: &sp1_sdk::SP1ProofWithPublicValues,
) -> Result<()> {
    let local_address = pubkey_to_address(public_key)?;

    let (committed_address, attestation_time) =
        nitro_verifier::decode_public_values(proof.public_values.as_slice())
            .map_err(|e| eyre!("Failed to decode attestation public values: {e}"))?;

    if committed_address != local_address {
        return Err(eyre!(
            "Committed enclave address mismatch: proof={committed_address}, local={local_address}"
        ));
    }

    info!(
        event = "attestation_l1_submitting",
        enclave_address = %local_address,
        attestation_time,
        "submitting attestation proof to l1",
    );

    let proof_bytes = proof.bytes();

    let wallet = EthereumWallet::from(config.l1_signer.clone());
    let provider =
        ProviderBuilder::new().wallet(wallet).connect_provider(config.l1_provider.clone());

    nitro_verifier::submit_attestation(
        &provider,
        config.nitro_verifier_addr,
        local_address,
        attestation_time,
        proof_bytes.into(),
    )
    .await?;

    Ok(())
}

/// Derive Ethereum address from 65-byte uncompressed secp256k1 public key.
pub(crate) fn pubkey_to_address(pubkey: &[u8]) -> Result<Address> {
    if pubkey.len() != 65 || pubkey[0] != 0x04 {
        return Err(eyre!(
            "Invalid uncompressed pubkey: len={}, first=0x{:02x}",
            pubkey.len(),
            pubkey.first().copied().unwrap_or(0)
        ));
    }
    let hash = alloy_primitives::keccak256(&pubkey[1..]);
    Ok(Address::from_slice(&hash[12..]))
}
