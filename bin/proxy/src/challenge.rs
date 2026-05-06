use std::{collections::HashSet, sync::Arc, time::Duration};

use alloy_primitives::Address;
use revm_primitives::{hex, B256};
use sp1_sdk::{
    network::{prover::NetworkProver, Error as Sp1NetworkError},
    ProveRequest, Prover, SP1ProvingKey, SP1Stdin,
};
use tracing::{info, warn};

use crate::attestation::{fetch_ha_prover_count, fetch_ha_whitelist, identify_fulfiller};

/// Wall-clock cap on a single `wait_proof` call. Bounded so a permanently-
/// stuck SP1 request can't hold the spawned task forever — `RequestTimedOut`
/// flows through the existing retriable branch.
const WAIT_PROOF_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Hard cap on the entire `run_challenge_proof` lifetime. After this the
/// worker exits with `set_challenge_failed` even if the SP1 network is
/// still serving retriable errors. Prevents orphaned background tasks
/// from running forever when the SP1 network is structurally broken.
const RUN_CHALLENGE_OUTER_BUDGET: Duration = Duration::from_secs(4 * 3600);

pub(crate) async fn run_challenge_proof(
    client: Arc<NetworkProver>,
    pk: Arc<SP1ProvingKey>,
    stdin: SP1Stdin,
    challenge_id: B256,
    block_number: u64,
) {
    let started = std::time::Instant::now();
    let mut blacklist: HashSet<Address> = HashSet::new();

    loop {
        if started.elapsed() > RUN_CHALLENGE_OUTER_BUDGET {
            warn!(
                event = "challenge_outer_budget_exceeded",
                request_id = %hex::encode(challenge_id),
                elapsed_secs = started.elapsed().as_secs(),
                "challenge outer budget exceeded — giving up",
            );
            if let Some(db) = crate::db::db() {
                db.set_challenge_failed(challenge_id, "outer wall-clock budget exceeded");
            }
            return;
        }

        let whitelist = match fetch_ha_whitelist(&blacklist).await {
            Ok(w) => w,
            Err(e) => {
                warn!(
                    event = "fetch_ha_whitelist_failed",
                    request_id = %hex::encode(challenge_id),
                    err = %e,
                    "fetch ha whitelist failed",
                );
                if let Some(db) = crate::db::db() {
                    db.set_challenge_failed(challenge_id, &format!("{e}"));
                }
                return;
            }
        };

        info!(
            event = "sp1_request_submitting",
            request_id = %hex::encode(challenge_id),
            block_number,
            whitelist_size = whitelist.len(),
            blacklist_size = blacklist.len(),
            "submitting challenge proof to sp1 network",
        );

        let id = match client
            .prove(pk.as_ref(), stdin.clone())
            .groth16()
            .max_price_per_pgu(500_000_000u64)
            .whitelist(Some(whitelist))
            .request()
            .await
        {
            Ok(id) => id,
            Err(e) => {
                warn!(
                    event = "sp1_request_submit_failed",
                    request_id = %hex::encode(challenge_id),
                    err = %e,
                    "sp1 request submit failed",
                );
                if let Some(db) = crate::db::db() {
                    db.set_challenge_failed(challenge_id, &format!("{e}"));
                }
                return;
            }
        };

        if let Some(db) = crate::db::db() {
            db.update_challenge_sp1_request_id(challenge_id, id);
        }

        info!(
            event = "sp1_request_submitted",
            request_id = %hex::encode(challenge_id),
            sp1_request_id = %hex::encode(id),
            "challenge proof submitted",
        );

        match client.wait_proof(id, Some(WAIT_PROOF_TIMEOUT), None).await {
            Ok(proof) => {
                info!(
                    event = "sp1_proof_ready",
                    request_id = %hex::encode(challenge_id),
                    "sp1 proof ready",
                );

                let proof_bytes = proof.bytes();
                let public_values = proof.public_values.as_slice().to_vec();
                if let Some(db) = crate::db::db() {
                    db.set_challenge_completed(challenge_id, &proof_bytes, &public_values);
                }
                return;
            }
            Err(e) => {
                let is_retriable = e.downcast_ref::<Sp1NetworkError>().is_some_and(|ne| {
                    matches!(
                        ne,
                        Sp1NetworkError::RequestUnfulfillable { .. } |
                            Sp1NetworkError::RequestTimedOut { .. } |
                            Sp1NetworkError::RequestAuctionTimedOut { .. }
                    )
                });

                if !is_retriable {
                    warn!(
                        event = "sp1_proof_failed_non_retriable",
                        request_id = %hex::encode(challenge_id),
                        err = %e,
                        "sp1 proof failed (non-retriable)",
                    );
                    if let Some(db) = crate::db::db() {
                        db.set_challenge_failed(challenge_id, &format!("{e}"));
                    }
                    return;
                }

                if let Some(fulfiller) = identify_fulfiller(&client, id).await {
                    warn!(
                        event = "challenge_prover_unfulfillable",
                        request_id = %hex::encode(challenge_id),
                        fulfiller = %fulfiller,
                        "challenge prover returned unfulfillable — blacklisting",
                    );
                    blacklist.insert(fulfiller);
                } else {
                    warn!(
                        event = "challenge_prover_unfulfillable_unknown",
                        request_id = %hex::encode(challenge_id),
                        "challenge proof failed, could not identify fulfiller",
                    );
                }

                let ha_count = fetch_ha_prover_count().await.unwrap_or(0);
                if ha_count > 0 && blacklist.len() >= ha_count {
                    warn!(
                        event = "ha_blacklist_reset",
                        blacklist_size = blacklist.len(),
                        "all ha provers blacklisted — resetting blacklist",
                    );
                    blacklist.clear();
                }
            }
        }
    }
}

/// Resume a previously-submitted SP1 request by polling the network with
/// the saved `sp1_request_id`. Used at proxy startup for rows whose
/// in-flight `tokio::spawn` task did not survive the process restart.
///
/// Mirrors the resume branch of `attestation::network::prove_and_submit_for_key`:
/// the SP1 network already holds the proof; we just need to retrieve it.
/// On retriable error (transient network), retry with the same request_id.
/// On non-retriable error (permanently lost), mark `failed` so the
/// orchestrator's existing 5xx → re-issue path generates a fresh request.
pub(crate) async fn resume_challenge_proof(
    client: Arc<NetworkProver>,
    challenge_id: B256,
    sp1_request_id: B256,
) {
    info!(
        event = "challenge_resume_starting",
        request_id = %hex::encode(challenge_id),
        sp1_request_id = %hex::encode(sp1_request_id),
        "resuming challenge proof from saved request id",
    );
    match client.wait_proof(sp1_request_id, Some(WAIT_PROOF_TIMEOUT), None).await {
        Ok(proof) => {
            let proof_bytes = proof.bytes();
            let public_values = proof.public_values.as_slice().to_vec();
            if let Some(db) = crate::db::db() {
                db.set_challenge_completed(challenge_id, &proof_bytes, &public_values);
            }
            info!(
                event = "challenge_resume_done",
                request_id = %hex::encode(challenge_id),
                "challenge resume done",
            );
        }
        Err(e) => {
            warn!(
                event = "challenge_resume_failed",
                request_id = %hex::encode(challenge_id),
                err = %e,
                "challenge resume failed — marking failed; orchestrator will re-issue",
            );
            if let Some(db) = crate::db::db() {
                db.set_challenge_failed(challenge_id, &format!("resume failed: {e}"));
            }
        }
    }
}
