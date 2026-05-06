//! Attestation driver: serialized handshake + per-key background prove tasks.

use std::{sync::Arc, time::Duration};

use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::types::NitroConfig;

use super::network::{prove_and_submit_for_key, AttestationConfig};

/// Serializes concurrent callers on the enclave's `NotInitialized` path.
/// Released as soon as one handshake completes, so subsequent enclave
/// restarts can trigger a fresh handshake.
static HANDSHAKE_LOCK: Mutex<()> = Mutex::const_new(());

/// Synchronous handshake + inline DB write + (on new key) spawn the background
/// prove task. Called from:
/// 1. startup in `main()` (blocks HTTP bind briefly)
/// 2. dispatch path in `enclave.rs` on `NotInitialized`
///
/// Spawn-dedup is inherent: we only spawn when `is_new_key=true`, and the
/// handshake lock ensures a second concurrent caller sees `AlreadyInitialized`.
pub(crate) async fn ensure_handshake(
    enclave: &NitroConfig,
    att_cfg: Option<&Arc<AttestationConfig>>,
) -> eyre::Result<()> {
    let _guard = HANDSHAKE_LOCK.lock().await;

    let (public_key, attestation, is_new_key) =
        crate::enclave::handshake_with_enclave(enclave).await?;

    if !is_new_key {
        info!(event = "enclave_already_initialised", "handshake: enclave already initialised");
        return Ok(());
    }

    if let Some(db) = crate::db::db() {
        db.insert_pending_attestation(&public_key, &attestation);
    }
    info!(
        event = "enclave_handshake_new_key",
        "handshake: new enclave key generated, pending attestation row inserted"
    );

    match att_cfg {
        Some(cfg) => {
            tokio::spawn(run_prove_loop(public_key, attestation, cfg.clone()));
        }
        None => warn!(
            event = "attestation_config_unavailable_skip_spawn",
            "attestation config not configured — skipping background prove task"
        ),
    }

    Ok(())
}

/// On startup, pick up every row in `pending_attestation` and spawn a
/// background prove task for it. Covers rows inserted by a previous proxy run
/// (old-key finish-through). Must run BEFORE the startup `ensure_handshake`
/// so that a matching handshake for an already-pending key is a no-op rather
/// than a duplicate spawn.
pub(crate) async fn resume_all_pending(att_cfg: Option<&Arc<AttestationConfig>>) {
    let Some(cfg) = att_cfg else {
        info!(
            event = "attestation_resume_skipped_no_config",
            "attestation config not configured — no pending attestations will be resumed"
        );
        return;
    };

    let rows = {
        let Some(db) = crate::db::db() else { return };
        db.load_pending_attestations()
    };

    if rows.is_empty() {
        info!(event = "attestation_resume_none", "no pending attestations to resume");
        return;
    }

    info!(
        event = "attestation_resume_started",
        count = rows.len(),
        "resuming pending attestations"
    );
    for row in rows {
        tokio::spawn(run_prove_loop(row.public_key, row.attestation, cfg.clone()));
    }
}

async fn run_prove_loop(public_key: Vec<u8>, attestation: Vec<u8>, cfg: Arc<AttestationConfig>) {
    let pk_hex = revm_primitives::hex::encode(&public_key);
    loop {
        match prove_and_submit_for_key(&cfg, &public_key, &attestation).await {
            Ok(()) => {
                info!(event = "attestation_complete", enclave_pubkey = %pk_hex, "attestation complete — l1 submission confirmed");
                return;
            }
            Err(e) => {
                warn!(
                    event = "attestation_run_failed",
                    enclave_pubkey = %pk_hex,
                    err = %e,
                    "attestation run failed — retrying in 30s",
                );
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        }
    }
}
