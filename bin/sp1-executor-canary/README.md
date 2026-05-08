# sp1-executor-canary

Silent canary that re-runs production L2 blocks through the pinned
`rsp-client` SP1 ELF (CPU emulation, no proof) and cross-checks the
committed public values against host-computed expected values.

On panic, public-values mismatch, or executor error: appends a row
to the local SQLite `divergences` table (append-only history;
composite PK `(block_number, ts)`) and increments a Prometheus
counter. The sidecar continues running.

## Architecture

```
[L2 RPC] → [Driver] → [MDBX + cold redb]
                          │
                  ┌───────┴────────┐
                  ▼                ▼
        [window_worker]    [Driver: produce_next_witness gated by
              │             max_lookahead_blocks via consumer_tip]
              ▼
        bounded async-channel (capacity = SP1_WORKERS * 2)
              │
       ┌──────┴──────┐
       ▼             ▼
  [sp1_worker 0] [sp1_worker N-1]
       │             │
       ▼             ▼
  ProverClient::cpu().execute() → verify public values
                                   ├─ Ok matches → counter, log info
                                   └─ Err / mismatch → SQLite + counter + log warn
```

The driver runs in the canary's own MDBX datadir (separate from the
orchestrator's). Driver back-pressure: workers update
`consumer_tip` after each block; the driver idles when
`block_number > consumer_tip + MAX_LOOKAHEAD_BLOCKS`.

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RPC_URL` | — | L2 RPC URL (drives forward sync). |
| `SP1_ELF_PATH` | — | Path to the pinned production `rsp-client-{NETWORK}.elf` artifact (must match the ELF deployed for `bin/proxy`; vk hash matches the on-chain `NitroVerifier`). |
| `WITNESS_FROM_BLOCK` | — | Optional explicit start cursor. If unset and SQLite is empty, the canary fetches the L2 RPC tip on first launch (skip ancient history). On restart, takes precedence over the SQLite resume cursor when set. |
| `DATADIR` | `./canary-driver` | Driver datadir (MDBX + static_files + RocksDB). |
| `WITNESS_COLD_FILE` | `<datadir>/cold.redb` | redb file for cold witness store. |
| `WITNESS_RETENTION_BLOCKS` | `172800` | Cold-store retention window in L2 blocks. |
| `MDBX_MAX_SIZE` | `549755813888` (512 GiB) | MDBX geometry max size in bytes. |
| `DB_PATH` | `./sp1_canary.db` | SQLite DB file (divergences + meta). |
| `L2_SAFE_BLOCKS` | `10` | L2 reorg-safety lag for the embedded driver. |
| `CANARY_WINDOW_SIZE` | `1024` | Fixed window of blocks per blob input build. Sidecar's own window — not tied to production batch boundaries. |
| `SP1_WORKERS` | `2` | Number of parallel SP1 worker tasks; each holds its own reused `ProverClient::cpu()`. |
| `MAX_LOOKAHEAD_BLOCKS` | `4096` | Hard cap on driver lookahead vs `consumer_tip` (= 4 windows of 1024). Must be `>= CANARY_WINDOW_SIZE` — startup fails fast otherwise (driver/window-worker would deadlock). |
| `CANARY_SKIP_EMPTY_BLOCKS` | `false` | When `true`/`1`/`yes`, blocks with zero transactions skip SP1 execute entirely and advance the watermark via the empty-block fast path. Counted via `canary_blocks_skipped_total`. |
| `FLUENT_METRICS_ADDR` | `0.0.0.0:9091` | HTTP listen address for the Prometheus `/metrics` endpoint. |
| `LOG_FORMAT` | `pretty` | `pretty` (dev) or `json` (Graylog-targeted via `tracing-format::ServiceJson`). |
| `DEPLOY_ENV` | `unknown` | Top-level `env` field in JSON log output. |
| `RUST_LOG` | (built-in) | Standard env-filter override. |

## Metrics

| Metric | Type | Labels | HELP |
|---|---|---|---|
| `canary_last_block_canaried` | gauge | — | Highest fully-canaried block (strict prefix; advances only when all prior blocks complete). |
| `canary_blocks_ok_total` | counter | — | Blocks where `client.execute()` returned Ok AND public values matched expected. |
| `canary_blocks_skipped_total` | counter | — | Empty blocks (zero txs) skipped via the empty-block fast path. |
| `canary_divergence_total` | counter | `kind` | SP1 canary divergences. |
| `canary_driver_mdbx_tip` | gauge | — | Canary driver's MDBX tip. |
| `canary_sp1_execute_duration_seconds` | histogram | — | Per-block duration of `ProverClient::cpu().execute()` (seconds). |

## Operator runbook

### First-time deployment

1. Build the production ELF: `make build-client-docker NETWORK=mainnet` →
   `rsp-client-mainnet.elf`. Same artifact deployed for `bin/proxy`.
2. Set env vars:
   ```
   RPC_URL=https://rpc.fluent.xyz
   SP1_ELF_PATH=./rsp-client-mainnet.elf
   DATADIR=./canary-driver
   DB_PATH=./sp1_canary.db
   FLUENT_METRICS_ADDR=0.0.0.0:9091
   ```
3. (Optional) Set `WITNESS_FROM_BLOCK=<recent block>` to skip ancient
   history. If unset, the canary starts at the current L2 tip.
4. `cargo run --release -p sp1-executor-canary --no-default-features --features mainnet`.

### Inspecting divergences

```
sqlite3 sp1_canary.db "SELECT block_number, datetime(ts, 'unixepoch'), kind, error \
                       FROM divergences ORDER BY ts DESC LIMIT 20"
```

Divergence kinds (per `db.rs::DivergenceKind`):
- Guest panic: `stf_failed`, `da_stf_mismatch`, `kzg_verify_failed`,
  `kzg_internal_error`, `blobs_*_length_mismatch`, `invalid_*_slice`,
  `deserialization_failed`.
- Public-values cross-check (guest didn't panic, output didn't match):
  `public_values_mismatch_{parent_hash,block_hash,withdrawal_hash,
  deposit_hash,versioned_hash,length}`.
- `unknown` — error string didn't match any known classifier.

### Tuning SP1_WORKERS

Start with `SP1_WORKERS=2` and increase based on observed CPU
saturation. Each worker holds its own `ProverClient::cpu()` and runs
fully CPU-bound during `execute()` calls. Practical upper bound is
`num_cpus()` minus overhead for the driver and tokio runtime.

### Resuming after a restart

The canary writes `last_canaried_block` to the meta table at the
**strict-prefix watermark** maintained by `CompletionTracker` —
advances only when block N AND all earlier blocks have completed.
SP1 workers complete blocks out of order; the watermark waits for
gaps to fill before advancing. On restart, `start_cursor =
last_canaried + 1` is guaranteed to be the first block whose work
was lost (no skips, no gaps). In-flight blocks below the watermark
were already accounted for; in-flight blocks above are re-dispatched
in full. Append-only history at the divergence row level absorbs any
re-runs idempotently.
