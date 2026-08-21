#!/usr/bin/env bash
# Update the deployed stack to a released version.
#
# Order is load-bearing twice over. Everything that can fail cheaply — version
# lookup, EIF download, PCR0 check, image pulls — runs before anything is
# stopped, so a bad tag or a broken download leaves the running stack alone.
# And the restart sequence is enclave -> proxy -> (attestation on L1) ->
# orchestrator, because each enclave launch mints a fresh ephemeral key whose
# public part has to be accepted on L1 before anything it signs is dispatchable.
#
# Outside the shell this uses only what operating this host already requires:
# curl, docker, nitro-cli. JSON is read with bash regex rather than jq — every
# field read here appears exactly once in its document.
set -euo pipefail

REPO="${REPO:-fluentlabs-xyz/fluent-stf}"
REGISTRY="${REGISTRY:-ghcr.io/${REPO}}"
ENCLAVE_CID="${ENCLAVE_CID:-10}"
ENCLAVE_CPUS="${ENCLAVE_CPUS:-6}"
ENCLAVE_MEMORY_MIB="${ENCLAVE_MEMORY_MIB:-4096}"
VERSION="${VERSION:-}"

log() { printf '\n== %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# Extract a string field from a JSON document. Each field read by this script
# occurs once in its document, so first-match is exact, not a heuristic.
json_str() {
    local json=$1 key=$2
    [[ $json =~ \"$key\"[[:space:]]*:[[:space:]]*\"([^\"]*)\" ]] || return 1
    printf '%s' "${BASH_REMATCH[1]}"
}

cd "$(dirname "$0")/.."

for cmd in docker curl nitro-cli; do
    command -v "$cmd" >/dev/null 2>&1 || die "$cmd is not installed"
done

# The deployment's network lives in .env; NETWORK_OVERRIDE is set by the
# Makefile only when the caller passed NETWORK explicitly. Without this the
# Makefile's own `NETWORK ?= mainnet` default would quietly pull mainnet images
# onto a testnet host — nothing at runtime cross-checks the two.
NETWORK="${NETWORK_OVERRIDE:-}"
if [ -z "$NETWORK" ]; then
    [ -f .env ] || die "no .env and no explicit NETWORK= — cannot tell which network this host runs"
    while IFS= read -r line || [ -n "$line" ]; do
        if [[ $line =~ ^NETWORK=[[:space:]]*\"?([A-Za-z]+)\"? ]]; then
            NETWORK="${BASH_REMATCH[1]}"
        fi
    done < .env
    [ -n "$NETWORK" ] || die "NETWORK is not set in .env"
fi
case "$NETWORK" in
    mainnet|testnet|devnet) ;;
    *) die "NETWORK must be one of: mainnet, testnet, devnet (got '$NETWORK')" ;;
esac

# ── 1. Resolve the version ───────────────────────────────────────────────────
if [ -z "$VERSION" ]; then
    releases_json=$(curl -sSf -H 'Accept: application/vnd.github+json' \
        "https://api.github.com/repos/${REPO}/releases/latest") \
        || die "could not reach the releases API for ${REPO}"
    VERSION=$(json_str "$releases_json" tag_name) \
        || die "no tag_name in the latest-release response"
fi
log "updating ${NETWORK} to ${VERSION}"

EIF="rsp-client-enclave-${NETWORK}.eif"
PCRS="${EIF}.pcrs.json"
ASSETS="https://github.com/${REPO}/releases/download/${VERSION}"
PROXY_IMAGE="${REGISTRY}/proxy:${NETWORK}-${VERSION}"
ORCHESTRATOR_IMAGE="${REGISTRY}/witness-orchestrator:${NETWORK}-${VERSION}"
export PROXY_IMAGE ORCHESTRATOR_IMAGE

# ── 2. Fetch and verify, without touching the running stack ──────────────────
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

log "downloading ${EIF}"
curl -fSL --progress-bar -o "${tmp}/${EIF}"  "${ASSETS}/${EIF}"
curl -fsSL               -o "${tmp}/${PCRS}" "${ASSETS}/${PCRS}"

# Catches a truncated download and a swapped asset before the enclave is asked
# to boot it. nitro-cli nests the value under Measurements while the flake's
# pcr.json has it at the top level — the same two shapes
# scripts/update_expected_pcr0.py accepts — and reading PCR0 by name covers both.
eif_json=$(nitro-cli describe-eif --eif-path "${tmp}/${EIF}")
measured=$(json_str "$eif_json" PCR0)   || die "no PCR0 in describe-eif output"
expected=$(json_str "$(<"${tmp}/${PCRS}")" PCR0) || die "no PCR0 in ${PCRS}"
[ "${measured,,}" = "${expected,,}" ] || die "PCR0 mismatch: eif=${measured}, pcrs.json=${expected}"
log "PCR0 ${measured}"

log "pulling images"
docker pull -q "$PROXY_IMAGE"
docker pull -q "$ORCHESTRATOR_IMAGE"

# ── 3. Stop ──────────────────────────────────────────────────────────────────
log "stopping containers"
docker compose down

enclaves_json=$(nitro-cli describe-enclaves)
if [[ $enclaves_json == *'"EnclaveID"'* ]]; then
    log "terminating enclave"
    nitro-cli terminate-enclave --all
fi

install -m 0644 "${tmp}/${EIF}"  "./${EIF}"
install -m 0644 "${tmp}/${PCRS}" "./${PCRS}"

# ── 4. Operator gate ─────────────────────────────────────────────────────────
cat <<'EOF'

The enclave comes up with a fresh ephemeral key, and the proxy retries its
attestation every 30s until L1 accepts it. If this release changed the
nitro-validator vkey, those retries cannot succeed until the new vkey is set on
L1 — but nothing needs re-triggering: the next retry goes through by itself.
EOF
read -r -p "Is the nitro-validator vkey on L1 already updated for ${VERSION}? [y/N] " answer
case "$answer" in
    [yY]*) ;;
    *) echo "Continuing — update the vkey on L1 while this waits." ;;
esac

# ── 5. Enclave ───────────────────────────────────────────────────────────────
log "starting enclave"
nitro-cli run-enclave \
    --eif-path "./${EIF}" \
    --cpu-count "$ENCLAVE_CPUS" \
    --memory "$ENCLAVE_MEMORY_MIB" \
    --enclave-cid "$ENCLAVE_CID"

# The AWS reference lists the states lowercase while its own example prints
# RUNNING, so compare case-insensitively.
state=""
for ((i = 0; i < 30; i++)); do
    enclaves_json=$(nitro-cli describe-enclaves)
    state=$(json_str "$enclaves_json" State || true)
    [ "${state,,}" = "running" ] && break
    sleep 2
done
[ "${state,,}" = "running" ] || die "enclave did not reach RUNNING (last state: '${state:-none}')"

# ── 6. Proxy, then wait for the attestation ──────────────────────────────────
since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
log "starting proxy"
docker compose up -d proxy

log "waiting for the attestation to be accepted on L1 (Ctrl-C to stop waiting)"
echo "  the proxy may restart a few times while the enclave finishes booting"

# The success line carries a tx hash and no key identity, so before trusting it
# the loop establishes that only one attestation can be in flight. The proxy
# reports that itself: resume_all_pending runs before the handshake and always
# emits exactly one of the first three lines below. A resumed row from an
# earlier interrupted run would produce a byte-identical success line for a
# different key — the gate is then meaningless, so the script stops instead of
# guessing. The `already` line is only conclusive when no new key was generated
# in this window: a proxy that restarts after a successful handshake logs both.
resumed='Resuming pending attestations'
no_pending='No pending attestations to resume'
no_att_cfg='AttestationConfig not configured'
newkey='Handshake: new enclave key generated'
already='Handshake: enclave already initialised'
success='Attestation verified on L1 successfully'

state_checked=0
while :; do
    logs=$(docker compose logs --no-color --no-log-prefix --since "$since" proxy 2>&1 || true)

    if [ "$state_checked" -eq 0 ]; then
        case "$logs" in
            *"$resumed"*)
                die "the proxy resumed attestation rows left over from an earlier run — its success log carries no key identity, so this wait cannot tell that key's attestation from this one's; resolve those rows before updating" ;;
            *"$no_att_cfg"*)
                die "the proxy is running without attestation proving — no attestation will ever be submitted" ;;
            *"$no_pending"*)
                state_checked=1 ;;
        esac
    fi

    if [ "$state_checked" -eq 1 ]; then
        case "$logs" in
            *"$success"*)
                log "attestation confirmed on L1"
                break
                ;;
        esac
        if [[ $logs != *"$newkey"* && $logs == *"$already"* ]]; then
            die "the proxy handshook with an already-initialised enclave — it was not replaced, so no attestation will be produced"
        fi
    fi

    printf '.'
    sleep 5
done

# ── 7. Orchestrator ──────────────────────────────────────────────────────────
log "starting witness-orchestrator"
docker compose up -d witness-orchestrator

log "done — ${NETWORK} is running ${VERSION}"
