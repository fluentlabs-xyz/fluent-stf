use std::sync::{Mutex, MutexGuard, OnceLock};

use revm_primitives::B256;
use rusqlite::{params, Connection};
use tracing::{error, warn};

static DB: OnceLock<Mutex<Db>> = OnceLock::new();

pub(crate) fn init(path: &str) -> eyre::Result<()> {
    let db = Db::open(path).map_err(|e| eyre::eyre!("Failed to open proxy database: {e}"))?;
    DB.set(Mutex::new(db)).map_err(|_| eyre::eyre!("Db already initialized"))
}

pub(crate) fn db() -> Option<MutexGuard<'static, Db>> {
    let mutex = DB.get()?;
    match mutex.lock() {
        Ok(guard) => Some(guard),
        Err(e) => {
            error!(event = "db_mutex_poisoned", err = %e, "db mutex poisoned");
            None
        }
    }
}

pub(crate) struct Db {
    conn: Connection,
}

impl Db {
    fn open(path: &str) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS pending_attestation (
                public_key   BLOB PRIMARY KEY,
                attestation  BLOB NOT NULL,
                request_id   BLOB,
                created_at   INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS challenges (
                challenge_id     BLOB PRIMARY KEY,
                sp1_request_id   BLOB,
                block_number     INTEGER NOT NULL,
                status           TEXT NOT NULL DEFAULT 'pending',
                proof_bytes      BLOB,
                public_values    BLOB,
                error            TEXT,
                created_at       INTEGER NOT NULL
            );
            DROP TABLE IF EXISTS attestation_request;
            ",
        )?;
        Ok(Self { conn })
    }

    // ── Pending attestations (per enclave key) ──────────────────────────

    pub(crate) fn insert_pending_attestation(&self, public_key: &[u8], attestation: &[u8]) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if let Err(e) = self.conn.execute(
            "INSERT INTO pending_attestation(public_key, attestation, request_id, created_at)
             VALUES(?1, ?2, NULL, ?3)
             ON CONFLICT(public_key) DO NOTHING",
            params![public_key, attestation, now],
        ) {
            warn!(event = "db_insert_pending_attestation_failed", err = %e, "db insert pending_attestation failed");
        }
    }

    pub(crate) fn load_pending_attestations(&self) -> Vec<PendingAttestation> {
        let mut stmt = match self
            .conn
            .prepare("SELECT public_key, attestation FROM pending_attestation")
        {
            Ok(s) => s,
            Err(e) => {
                warn!(event = "db_load_pending_attestations_prepare_failed", err = %e, "db load_pending_attestations prepare failed");
                return Vec::new();
            }
        };
        let rows = stmt.query_map([], |row| {
            Ok(PendingAttestation { public_key: row.get(0)?, attestation: row.get(1)? })
        });
        match rows {
            Ok(iter) => iter.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                warn!(event = "db_query_pending_attestation_failed", err = %e, "db query pending_attestation failed");
                Vec::new()
            }
        }
    }

    pub(crate) fn get_request_id(&self, public_key: &[u8]) -> Option<B256> {
        let bytes: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT request_id FROM pending_attestation WHERE public_key = ?1",
                params![public_key],
                |row| row.get(0),
            )
            .ok()?;
        bytes.and_then(|b| B256::try_from(b.as_slice()).ok())
    }

    pub(crate) fn set_request_id(&self, public_key: &[u8], request_id: B256) {
        if let Err(e) = self.conn.execute(
            "UPDATE pending_attestation SET request_id = ?2 WHERE public_key = ?1",
            params![public_key, request_id.as_slice()],
        ) {
            warn!(event = "db_update_request_id_failed", err = %e, "db update request_id failed");
        }
    }

    pub(crate) fn clear_request_id(&self, public_key: &[u8]) {
        if let Err(e) = self.conn.execute(
            "UPDATE pending_attestation SET request_id = NULL WHERE public_key = ?1",
            params![public_key],
        ) {
            warn!(event = "db_clear_request_id_failed", err = %e, "db clear request_id failed");
        }
    }

    pub(crate) fn delete_pending_attestation(&self, public_key: &[u8]) {
        if let Err(e) = self
            .conn
            .execute("DELETE FROM pending_attestation WHERE public_key = ?1", params![public_key])
        {
            warn!(event = "db_delete_pending_attestation_failed", err = %e, "db delete pending_attestation failed");
        }
    }

    // ── Challenge tracking ──────────────────────────────────────────────

    pub(crate) fn create_challenge(&self, challenge_id: B256, block_number: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if let Err(e) = self.conn.execute(
            "INSERT INTO challenges(challenge_id, block_number, status, created_at)
             VALUES(?1, ?2, 'pending', ?3)",
            params![challenge_id.as_slice(), block_number, now],
        ) {
            warn!(event = "db_create_challenge_failed", err = %e, "db create challenge failed");
        }
    }

    pub(crate) fn update_challenge_sp1_request_id(&self, challenge_id: B256, sp1_request_id: B256) {
        if let Err(e) = self.conn.execute(
            "UPDATE challenges SET sp1_request_id = ?2 WHERE challenge_id = ?1",
            params![challenge_id.as_slice(), sp1_request_id.as_slice()],
        ) {
            warn!(event = "db_update_challenge_sp1_request_id_failed", err = %e, "db update challenge sp1_request_id failed");
        }
    }

    pub(crate) fn set_challenge_completed(
        &self,
        challenge_id: B256,
        proof_bytes: &[u8],
        public_values: &[u8],
    ) {
        if let Err(e) = self.conn.execute(
            "UPDATE challenges SET status = 'completed', proof_bytes = ?2, public_values = ?3
             WHERE challenge_id = ?1",
            params![challenge_id.as_slice(), proof_bytes, public_values,],
        ) {
            warn!(event = "db_set_challenge_completed_failed", err = %e, "db set challenge completed failed");
        }
    }

    pub(crate) fn set_challenge_failed(&self, challenge_id: B256, err_msg: &str) {
        if let Err(e) = self.conn.execute(
            "UPDATE challenges SET status = 'failed', error = ?2 WHERE challenge_id = ?1",
            params![challenge_id.as_slice(), err_msg],
        ) {
            warn!(event = "db_set_challenge_failed_failed", err = %e, "db set challenge failed failed");
        }
    }

    pub(crate) fn get_challenge(&self, challenge_id: B256) -> Option<ChallengeRow> {
        self.conn
            .query_row(
                "SELECT status, proof_bytes, public_values, error
                 FROM challenges WHERE challenge_id = ?1",
                params![challenge_id.as_slice()],
                |row| {
                    Ok(ChallengeRow {
                        status: row.get(0)?,
                        proof_bytes: row.get(1)?,
                        public_values: row.get(2)?,
                        error: row.get(3)?,
                    })
                },
            )
            .ok()
    }

    /// Snapshot of every challenge row still in `pending`. Used at proxy
    /// startup to re-spawn `wait_proof` workers for in-flight SP1
    /// requests that survived a process restart. Rows that have a
    /// `sp1_request_id` get a fresh `wait_proof` worker; rows without
    /// one are marked `failed` so the orchestrator's existing 5xx →
    /// re-issue path takes over.
    pub(crate) fn load_pending_challenges(&self) -> Vec<PendingChallenge> {
        let mut stmt = match self
            .conn
            .prepare("SELECT challenge_id, sp1_request_id FROM challenges WHERE status = 'pending'")
        {
            Ok(s) => s,
            Err(e) => {
                warn!(event = "db_load_pending_challenges_prepare_failed", err = %e, "db load_pending_challenges prepare failed");
                return Vec::new();
            }
        };
        let rows = stmt.query_map([], |row| {
            let cid_blob: Vec<u8> = row.get(0)?;
            let sp1_blob: Option<Vec<u8>> = row.get(1)?;
            let challenge_id = B256::try_from(cid_blob.as_slice()).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Blob,
                    Box::new(std::io::Error::other(format!("challenge_id: {e}"))),
                )
            })?;
            let sp1_request_id = sp1_blob.and_then(|b| B256::try_from(b.as_slice()).ok());
            Ok(PendingChallenge { challenge_id, sp1_request_id })
        });
        match rows {
            Ok(iter) => iter.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                warn!(event = "db_query_pending_challenges_failed", err = %e, "db query pending challenges failed");
                Vec::new()
            }
        }
    }
}

pub(crate) struct PendingChallenge {
    pub challenge_id: B256,
    pub sp1_request_id: Option<B256>,
}

pub(crate) struct ChallengeRow {
    pub status: String,
    pub proof_bytes: Option<Vec<u8>>,
    /// Persisted for operator inspection (`sqlite3 proxy.db`); not
    /// forwarded over the wire — the Rollup contract reconstructs
    /// publicValues itself from header + blob hashes.
    #[allow(dead_code)]
    pub public_values: Option<Vec<u8>>,
    pub error: Option<String>,
}

pub(crate) struct PendingAttestation {
    pub public_key: Vec<u8>,
    pub attestation: Vec<u8>,
}
