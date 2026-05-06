# witness-orchestrator

Sidecar that drives Fluent L2 forward-sync, calls a remote Nitro proxy
for signed execution + batch-root signing, accumulates batches, submits
`preconfirmBatch` to L1, and resolves challenges via SP1.

## Binaries

- `witness-orchestrator` — long-running daemon.
- `send_challenge_block` — operator-only one-shot CLI: submits
  `Rollup.challengeBlock(batchIndex, blockHeader, blockProof)` with the
  contract's challenge bond so a running daemon picks up the resulting
  `BlockChallenged` event and resolves it. Used for manual testing or
  recovery drills.

### Daemon (`witness-orchestrator`)

| Variable | Default | Description |
|----------|---------|-------------|
| `RPC_URL` | — | L2 RPC URL (drives forward sync, blob construction, witness rebuild). |
| `L1_RPC_URL` | — | L1 Ethereum RPC URL (events + writes). |
| `L1_ROLLUP_ADDR` | — | Rollup contract address on L1. |
| `L1_SUBMITTER_KEY` | — | Private key for `preconfirmBatch` txs. **Exclusive use** — see CLAUDE.md "L1 submitter wallet". |
| `API_KEY` | — | API key forwarded to the proxy on every request. |
| `DATADIR` | `./forward-driver` | Driver datadir (MDBX + static_files + RocksDB). |
| `WITNESS_COLD_FILE` | `<datadir>/cold.redb` | redb file for cold witness store. |
| `WITNESS_RETENTION_BLOCKS` | `172800` | Cold-store retention window in L2 blocks. `0` = archive mode (no pruning). |
| `MDBX_MAX_SIZE` | `549755813888` (512 GiB) | MDBX geometry max size in bytes. |
| `PROXY_URL` | `http://127.0.0.1:8080` | Remote proxy base URL. |
| `DB_PATH` | `./witness_orchestrator.db` | SQLite DB for crash recovery. |
| `HTTP_TIMEOUT_SECS` | `120` | HTTP POST timeout (seconds). |
| `L1_START_BATCH_ID` | — | If set (and no checkpoint in DB), scan L1 to derive the L2 start checkpoint. |
| `L1_ROLLUP_DEPLOY_BLOCK` | `0` | L1 block where Rollup contract was deployed (lower bound for event scans). |
| `L1_POLL_INTERVAL_SECS` | `60` | L1 listener poll cadence. |
| `L1_SAFE_BLOCKS` | `7` | L1 reorg-safety lag (blocks treated as unfinalized). |
| `L2_SAFE_BLOCKS` | `10` | L2 reorg-safety lag for the embedded driver (`remote_tip - L2_SAFE_BLOCKS`). |
| `RBF_BUMP_INTERVAL_SECS` | `15` | Per-bump sleep in the RBF loop. |
| `RBF_BUMP_PERCENT` | `20` | Per-bump fee multiplier (must satisfy EIP-1559's +12.5% minimum). |
| `RBF_MAX_FEE_PER_GAS_WEI` | `500000000000` | Hard fee cap; reaching it is an operator-attention event. |
| `FLUENT_METRICS_ADDR` | `0.0.0.0:9090` | HTTP listen address for the Prometheus `/metrics` endpoint. |
| `HEARTBEAT_INTERVAL_SECS` | `300` | Cadence of the consolidated heartbeat log line. |
| `LOG_FORMAT` | `pretty` | `pretty` (dev) or `json` (Graylog-targeted via `tracing-format::ServiceJson`). |
| `DEPLOY_ENV` | `unknown` | Top-level `env` field in JSON log output. |
| `RUST_LOG` | (built-in) | Standard env-filter override. Default trims `alloy/reth/hyper/...=warn`; set `RUST_LOG=info,alloy=debug` to re-enable specific crates. |

### Operator CLI (`send_challenge_block`)

| Variable | Description |
|----------|-------------|
| `RPC_URL` | L2 RPC URL (used to build `L2BlockHeader` for every block in the batch). |
| `L1_RPC_URL` | L1 Ethereum RPC URL. |
| `L1_ROLLUP_ADDR` | Rollup contract address. |
| `L1_CHALLENGER_KEY` | Challenger private key — MUST hold `CHALLENGER_ROLE` and MUST NOT be the orchestrator's `L1_SUBMITTER_KEY`. |
| `CHALLENGE_BATCH_INDEX` | Index of the batch containing the disputed block. |
| `CHALLENGE_BLOCK_NUMBER` | L2 block number to dispute (must lie inside `CHALLENGE_BATCH_INDEX`). |

## Metrics

Prometheus `/metrics` is served at `FLUENT_METRICS_ADDR` (default
`0.0.0.0:9090`). Metric names and HELP strings are defined in
`src/metrics.rs` via `describe_*!` macros; the live `/metrics` endpoint
is the canonical reference. Categories:

- **Progress gauges** (`orchestrator_last_block_*`, `orchestrator_last_batch_*`)
  — pipeline tip and most-recently-signed / preconfirmed batch.
- **Duration histograms** (`orchestrator_sign_block_execution_duration_seconds`,
  `orchestrator_sign_batch_root_duration_seconds`).
- **Error / failure counters** (`orchestrator_sign_failures_total`,
  `orchestrator_l1_dispatch_rejected_total`, `orchestrator_l1_broadcast_failures_total`).
- **Cost histogram** (`orchestrator_l1_dispatch_cost_eth`) — per-tx ETH
  cost; cumulative spend via the Prometheus `_sum` counterpart.
- **Nonce-allocator drift** (`orchestrator_nonce_allocator_next`,
  `orchestrator_nonce_pending_l1`, `orchestrator_nonce_leaks_total`) —
  see `NonceAllocator` in `crates/l1-rollup-client`.
- **Resolve-tx counters** (`orchestrator_l1_resolve_*`) — per-kind
  (`block` | `batch_root`) lifecycle counters for challenge resolution.
- **Challenge-flow counters** (`orchestrator_challenge_*`) — invariant
  violations, deadline expiries, SP1 request loss, post-mine reverts,
  reorg detections.
- **DB writer drops** (`orchestrator_db_writer_dropped_total`) — accumulator
  mutations dropped because the DB writer channel was closed (typically
  during shutdown).