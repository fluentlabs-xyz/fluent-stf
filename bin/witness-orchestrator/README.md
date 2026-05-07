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
`0.0.0.0:9090`). All metrics are registered with `describe_*!` HELP
strings in `src/metrics.rs::install`; this section is the canonical
reference (the live `/metrics` endpoint mirrors it verbatim).

### Progress gauges

Operator-facing pipeline watermarks. All monotonic non-decreasing.
Seeded on startup from SQLite via `seed_gauges_on_startup` so panels
render before the first live event arrives.

| Metric | Type | Labels | HELP | When to investigate |
|---|---|---|---|---|
| `orchestrator_last_block_witness_built` | gauge | — | Latest L2 block number for which a witness is available (built fresh or reused from cold store). | Should advance at the L2 block rate. Stalled = driver/RPC issue. |
| `orchestrator_last_block_executed` | gauge | — | Latest L2 block number executed by the proxy/enclave. | Should trail `_witness_built` by ≤ a handful of blocks. Wider gap = sign endpoint slow / saturated. |
| `orchestrator_last_block_signed` | gauge | — | Latest L2 block number included in a signed batch (equals `_last_batch_signed_to_block`). Difference from `_last_block_executed` surfaces blocks-executed-but-not-yet-in-signed-batch. | Persistent gap = signer/cache stalled. |
| `orchestrator_last_batch_signed` | gauge | — | Index of the most recently signed L1 batch (`/sign-batch-root`). | Should rise per batch. |
| `orchestrator_last_batch_signed_from_block` | gauge | — | from_block of the most recently signed batch. | Pair with `_to_block` to bound the batch's L2 range. |
| `orchestrator_last_batch_signed_to_block` | gauge | — | to_block of the most recently signed batch. | Equals `_last_block_signed` by construction. |
| `orchestrator_last_batch_preconfirmed` | gauge | — | Index of the most recently L1-included preconfirmBatch observed via `BatchPreconfirmed` event. | Should trail `_last_batch_signed` by ≤ a few batches. |
| `orchestrator_last_batch_preconfirmed_from_block` | gauge | — | from_block of the most recently L1-included batch. | — |
| `orchestrator_last_batch_preconfirmed_to_block` | gauge | — | to_block of the most recently L1-included batch. | — |

### Sign endpoint histograms

Per-attempt latency for the two HTTP endpoints the orchestrator calls
on the proxy. Histograms are recorded on EVERY attempt (success or
failure), so `_count` doubles as the attempt counter (consumed by the
dashboard's Sign Success ratio formula).

Bucket layout: `[0.5, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024,
2048, 4096, 8192]` seconds — exponential base 2. Top buckets sized
defensively against SP1 cold-start outliers; if `+Inf` ever
accumulates samples, the dashboard sentinel surfaces it.

| Metric | Type | Labels | HELP | When to investigate |
|---|---|---|---|---|
| `orchestrator_sign_block_execution_duration_seconds` | histogram | — | Per-attempt duration of `/sign-block-execution` HTTP call (seconds). | p95 > 60 s under steady load = SP1/enclave slow. p99 pegged at 8192 s = bucket overflow (sentinel panel). |
| `orchestrator_sign_batch_root_duration_seconds` | histogram | — | Per-attempt duration of `/sign-batch-root` HTTP call (seconds). | p95 > 2 s = enclave slow on signing. |

### Sign endpoint failure counter

| Metric | Type | Labels | HELP | When to investigate |
|---|---|---|---|---|
| `orchestrator_sign_failures_total` | counter | `stage`={block,batch}, `kind`={enclave_busy,other} | Sign-endpoint failures. | `enclave_busy` rate spikes pair with Exec→Sign lag growth (queue saturation); `other` bursts = network/proxy issues. |

### L1 dispatch counters

| Metric | Type | Labels | HELP | When to investigate |
|---|---|---|---|---|
| `orchestrator_l1_broadcast_failures_total` | counter | `kind`={nonce_too_low,stuck_at_cap,other} | preconfirmBatch broadcast attempts rejected by the L1 RPC before mempool admission. | `nonce_too_low` = wallet exclusivity violation or NonceAllocator drift. `stuck_at_cap` = `RBF_MAX_FEE_PER_GAS_WEI` hit (operator attention). |
| `orchestrator_l1_dispatch_rejected_total` | counter | `kind`={oog,logic} | preconfirmBatch txs that were mined with status=0 (on-chain revert). | `oog` retries with re-estimated gas. `logic` = contract revert (NitroVerifierNotEnabled, RollupCorrupted) — investigate. |
| `orchestrator_l1_dispatch_cost_eth` | histogram | — | Per-tx ETH cost of L1 preconfirmBatch (`gas_used × effective_gas_price / 1e18`). Cumulative via `_sum`. | p99 climbing faster than p50 = fee-bump loop on stuck txs. |

Bucket layout for `_l1_dispatch_cost_eth`: `[1e-5, 2e-5, 4e-5, 8e-5,
1.6e-4, 3.2e-4, 6.4e-4, 1.28e-3, 2.56e-3, 5.12e-3, 1.024e-2, 2.048e-2,
4.096e-2, 8.192e-2, 1.6384e-1, 3.2768e-1, 6.5536e-1]` ETH —
exponential base 2, 10 µETH to ~0.65 ETH.

### Resolve-tx counters

Per-kind lifecycle counters for challenge resolve transactions.

| Metric | Type | Labels | HELP | When to investigate |
|---|---|---|---|---|
| `orchestrator_l1_resolve_dispatched_total` | counter | `kind`={block,batch_root} | Resolve-tx broadcasts (first attempt per challenge). | Baseline rate ≈ challenge rate. |
| `orchestrator_l1_resolve_submitted_total` | counter | `kind`={block,batch_root} | Resolve-tx receipts observed with status=1. | Should equal `_dispatched_total` over the challenge's lifetime. |
| `orchestrator_l1_resolve_rejected_total` | counter | `kind`={block,batch_root} | Resolve-tx receipts observed with status=0 (on-chain revert). | Non-zero = SP1 proof rejected on-chain or input mismatch — investigate. |
| `orchestrator_l1_resolve_pre_receipt_failure_total` | counter | `kind`={block,batch_root} | Resolve-tx hard-failures before any receipt (initial broadcast error, stuck-at-cap, nonce advanced). | Non-zero = challenger wallet / nonce issue or fee-cap reached. |

### Challenge sentinels

These should remain at 0 in normal operation. Any non-zero rate is
operator-attention-worthy.

| Metric | Type | Labels | HELP | When to investigate |
|---|---|---|---|---|
| `orchestrator_challenge_deadline_expired_total` | counter | `kind`={block,batch_root} | Challenges that crossed the on-chain resolution deadline before a successful resolve tx mined. | Operator must call `Rollup.revertBatches`. Rollup wedged. |
| `orchestrator_challenge_invariant_violation_total` | counter | `kind`={block,batch_root} | Challenge rows transitioned to Failed because an invariant the resolver assumes is violated (missing batch in DB, commitment outside batch range, etc.). | DB corruption or upstream protocol mismatch. |
| `orchestrator_challenge_sp1_request_lost_total` | counter | `kind`={block,batch_root} | Proxy returned 404 for an SP1 request id we issued. | Proxy DB wipe / restart with stale state. Orchestrator auto-recovers by re-issuing. |
| `orchestrator_challenge_pre_broadcast_failed_total` | counter | `kind`={block,batch_root} | Resolve-tx failed pre-broadcast `eth_call` simulation. | Permanent contract revert; resolve abandoned. |
| `orchestrator_challenge_reverted_post_mine_total` | counter | — | Resolve-tx receipt observed status=0 by the finalization ticker (RBF receipt-watcher missed the failure earlier). | RBF state cleared for retry. |
| `orchestrator_challenge_reorg_detected_total` | counter | — | Challenge resolve-tx receipt vanished — suspected L1 reorg. l1_block cleared so the active worker re-broadcasts. | Frequent = unstable L1. |
| `orchestrator_batch_reorg_detected_total` | counter | — | preconfirmBatch tx receipt vanished after `BatchPreconfirmed` event — suspected L1 reorg. Status rolled back to Dispatched; dispatcher resumes RBF against the persisted nonce. | Frequent = unstable L1. |

### Nonce allocator

USE-style resource view of the L1 submitter wallet's nonce slot. See
`NonceAllocator` in `crates/l1-rollup-client` for the underlying type.

| Metric | Type | Labels | HELP | When to investigate |
|---|---|---|---|---|
| `orchestrator_nonce_allocator_next` | gauge | — | NonceAllocator's next-to-issue nonce (peek of the atomic counter). Compare with `_nonce_pending_l1` to spot drift. | Should advance with each dispatch. Frozen = no in-flight dispatches. |
| `orchestrator_nonce_pending_l1` | gauge | — | L1 pending nonce for the orchestrator's submitter wallet (`eth_getTransactionCount(signer, pending)`). Refreshed on bootstrap, after nonce-too-low resync, and once per `FINALIZATION_TICK` (~30 s). | Drift `_next - _pending_l1` > a few tens = stuck mempool / chain congestion. |
| `orchestrator_nonce_leaks_total` | counter | — | Times `NonceAllocator::release_with_outcome` could not rewind the counter due to a concurrent `allocate()`. Sentinel — should remain 0 after the defer-allocate refactor. | Non-zero = regression of the defer-allocate invariant. |

### DB writer

| Metric | Type | Labels | HELP | When to investigate |
|---|---|---|---|---|
| `orchestrator_db_writer_dropped_total` | counter | — | Accumulator mutations dropped because the DB writer channel was closed (typically during shutdown). In-memory state may be ahead of DB; restart resyncs via `normalize_startup_checkpoint`. | Non-zero outside shutdown = writer task exited unexpectedly. |