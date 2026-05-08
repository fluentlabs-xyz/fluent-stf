//! SQLite-backed persistence for the SP1 canary.
//!
//! Two tables:
//!   `divergences` — append-only history. Composite PK `(block_number, ts)`
//!     so the same block can accumulate multiple rows over re-runs.
//!   `meta` — single-row table holding the resume cursor
//!     (`last_canaried_block`).

use std::{path::Path, sync::Mutex, time::SystemTime};

use rusqlite::{params, Connection};
use tracing::warn;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS divergences (
    block_number INTEGER NOT NULL,
    ts           INTEGER NOT NULL,
    kind         TEXT NOT NULL,
    error        TEXT NOT NULL,
    PRIMARY KEY (block_number, ts)
);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DivergenceKind {
    StfFailed,
    DaStfMismatch,
    KzgVerifyFailed,
    KzgInternalError,
    BlobsCommitmentsLengthMismatch,
    BlobsProofsLengthMismatch,
    InvalidBlobSlice,
    InvalidCommitmentSlice,
    InvalidProofSlice,
    DeserializationFailed,
    PublicValuesMismatchLength,
    PublicValuesMismatchParentHash,
    PublicValuesMismatchBlockHash,
    PublicValuesMismatchWithdrawalHash,
    PublicValuesMismatchDepositHash,
    PublicValuesMismatchVersionedHash,
    Unknown,
}

impl DivergenceKind {
    pub(crate) fn as_static_str(self) -> &'static str {
        match self {
            Self::StfFailed => "stf_failed",
            Self::DaStfMismatch => "da_stf_mismatch",
            Self::KzgVerifyFailed => "kzg_verify_failed",
            Self::KzgInternalError => "kzg_internal_error",
            Self::BlobsCommitmentsLengthMismatch => "blobs_commitments_length_mismatch",
            Self::BlobsProofsLengthMismatch => "blobs_proofs_length_mismatch",
            Self::InvalidBlobSlice => "invalid_blob_slice",
            Self::InvalidCommitmentSlice => "invalid_commitment_slice",
            Self::InvalidProofSlice => "invalid_proof_slice",
            Self::DeserializationFailed => "deserialization_failed",
            Self::PublicValuesMismatchLength => "public_values_mismatch_length",
            Self::PublicValuesMismatchParentHash => "public_values_mismatch_parent_hash",
            Self::PublicValuesMismatchBlockHash => "public_values_mismatch_block_hash",
            Self::PublicValuesMismatchWithdrawalHash => "public_values_mismatch_withdrawal_hash",
            Self::PublicValuesMismatchDepositHash => "public_values_mismatch_deposit_hash",
            Self::PublicValuesMismatchVersionedHash => "public_values_mismatch_versioned_hash",
            Self::Unknown => "unknown",
        }
    }
}

pub(crate) fn open(path: &Path) -> eyre::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

pub(crate) fn read_last_canaried_block(conn: &Connection) -> eyre::Result<Option<u64>> {
    let row: Option<i64> = conn
        .query_row("SELECT value FROM meta WHERE key = 'last_canaried_block'", [], |r| r.get(0))
        .ok();
    Ok(row.map(|v| v as u64))
}

/// Monotonic update — writes `block` only if it is strictly greater than
/// the currently-stored value. Required because SP1 workers complete out
/// of order (worker A may finish block 100 before worker B finishes
/// block 50; without `MAX(...)` we'd regress the cursor).
pub(crate) fn write_last_canaried_block(db: &Mutex<Connection>, block: u64) {
    let conn = db.lock().unwrap_or_else(|e| e.into_inner());
    if let Err(e) = conn.execute(
        "INSERT INTO meta(key, value) VALUES('last_canaried_block', ?1) \
         ON CONFLICT(key) DO UPDATE SET value=MAX(value, excluded.value)",
        params![block as i64],
    ) {
        warn!(event = "meta_write_failed", err = %e, block, "write last_canaried_block failed");
    }
}

pub(crate) fn append_divergence(
    db: &Mutex<Connection>,
    block_number: u64,
    kind: DivergenceKind,
    error: &str,
) {
    let ts =
        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let conn = db.lock().unwrap_or_else(|e| e.into_inner());
    if let Err(e) = conn.execute(
        "INSERT INTO divergences(block_number, ts, kind, error) VALUES(?1, ?2, ?3, ?4)",
        params![block_number as i64, ts as i64, kind.as_static_str(), error],
    ) {
        warn!(
            event = "divergence_insert_failed",
            err = %e,
            block_number,
            kind = kind.as_static_str(),
            "divergence insert failed"
        );
    }
}
