.PHONY: build-client-docker build-nitro-validator-docker \
        build-enclave build-enclave-docker build-proxy build-canary build-release \
        run run-sp1-only run-enclave clean help \
        compose-build compose-up compose-down compose-logs download-genesis-cache \
        compose-build-canary compose-up-canary compose-down-canary compose-logs-canary

# ─── Paths ────────────────────────────────────────────────────────────────────
CLIENT_DIR   := bin/client
PROXY_DIR    := bin/proxy

# ─── Docker Compose (v2 plugin or standalone) ─────────────────────────────────
DOCKER_COMPOSE := $(shell docker compose version >/dev/null 2>&1 && echo "docker compose" || echo "docker-compose")

# ─── Network (mainnet | testnet | devnet) ────────────────────────────────────
NETWORK      ?= mainnet
ifeq ($(filter $(NETWORK),mainnet testnet devnet),)
$(error NETWORK must be one of: mainnet, testnet, devnet (got '$(NETWORK)'))
endif

# ─── Nitro / enclave (network-tagged artifacts) ───────────────────────────────
TARGET       := x86_64-unknown-linux-musl
BINARY       := rsp-client
EIF          := rsp-client-enclave-$(NETWORK).eif
ELF          := rsp-client-$(NETWORK).elf

# ─── Nitro validator (attestation proving) ────────────────────────────────────
NITRO_VALIDATOR_DIR := bin/aws-nitro-validator
NITRO_VALIDATOR_ELF := nitro-validator-$(NETWORK).elf

# ─── Config (override via env or CLI) ─────────────────────────────────────────
EIF_PATH     ?= $(EIF)
ELF_PATH     ?= $(ELF)
API_KEY      ?= secret
LISTEN_ADDR  ?= 0.0.0.0:8080
SP1_PROVER   ?= network          # cpu | network
RUST_LOG 	 ?= info

# ─── SP1 ELF ──────────────────────────────────────────────────────────────────

## Build the rsp-client ELF via the pinned SP1 toolchain stage in Dockerfile.
## BuildKit compiles the `sp1-client-elf-builder` stage inside ghcr.io/
## succinctlabs/sp1 (no host cargo-prove needed) and the `sp1-client-elf-export`
## scratch stage writes exactly one file (rsp-client-$(NETWORK).elf) to the
## repo root via `--output type=local`. Genesis cache must be pre-populated
## because the builder stage copies it from .docker-cache/genesis.
build-client-docker: download-genesis-cache
	DOCKER_BUILDKIT=1 docker build \
		--target sp1-client-elf-export \
		--build-arg NETWORK=$(NETWORK) \
		--output type=local,dest=. \
		--no-cache \
		-f Dockerfile .
	@if [ -f nitro-validator-$(NETWORK).vkey ]; then \
		python3 scripts/update_readme_vkeys.py \
			rsp-client-$(NETWORK).vkey \
			nitro-validator-$(NETWORK).vkey \
			README.md \
			$(NETWORK); \
	else \
		echo "note: nitro-validator-$(NETWORK).vkey missing — skipping README vkey update (run build-nitro-validator-docker to populate)"; \
	fi

# ─── Nitro validator ELF (attestation proving) ───────────────────────────────

## Build the nitro-validator ELF via the Dockerfile, same mechanism as
## build-client-docker. No genesis cache dependency — the validator crate is
## a standalone workspace with no fluent-stf-primitives build.rs to feed.
build-nitro-validator-docker:
	DOCKER_BUILDKIT=1 docker build \
		--target nitro-validator-elf-export \
		--build-arg NETWORK=$(NETWORK) \
		--output type=local,dest=. \
		--no-cache \
		-f Dockerfile .
	@if [ -f rsp-client-$(NETWORK).vkey ]; then \
		python3 scripts/update_readme_vkeys.py \
			rsp-client-$(NETWORK).vkey \
			nitro-validator-$(NETWORK).vkey \
			README.md \
			$(NETWORK); \
	else \
		echo "note: rsp-client-$(NETWORK).vkey missing — skipping README vkey update (run build-client-docker to populate)"; \
	fi

# ─── Nitro enclave ────────────────────────────────────────────────────────────

## Build .eif for AWS Nitro reproducibly via Nix + monzo/aws-nitro-util.
## PCR0 is determined entirely by the flake (pinned nixpkgs + nitro-util blobs
## + pinned rust toolchain + git-hashed source tree) — any machine with Nix
## produces the same PCR0. `--impure` is needed on first build to let
## builtins.fetchGit pull git dependencies from the Cargo.lock; subsequent
## builds hit the store. Writes EIF + pcr.json into the repo root and rewrites
## EXPECTED_PCR0 for $(NETWORK) in nitro-validator lib.rs and the matching
## sentinel in README.md.
build-enclave:
	@command -v nix >/dev/null 2>&1 || { echo "error: nix not installed (see https://determinate.systems/nix)"; exit 1; }
	nix --extra-experimental-features 'nix-command flakes' build .#enclave-$(NETWORK) --impure
	install -m 0644 result/image.eif $(EIF)
	install -m 0644 result/pcr.json  $(EIF).pcrs.json
	python3 scripts/update_expected_pcr0.py \
		$(EIF).pcrs.json \
		bin/aws-nitro-validator/src/lib.rs \
		$(NETWORK) \
		--readme README.md
	@echo "EIF: $(EIF)"
	@echo "PCR0: $$(jq -r .PCR0 $(EIF).pcrs.json)"

## Build .eif inside a docker container running nixos/nix, so the host
## machine doesn't need Nix installed. PCR0 is identical to host-built
## because every input is pinned by the flake. A named docker volume
## (`rsp-nix-store`) persists /nix across runs so subsequent builds are
## incremental. Output is chowned back to the invoking user.
build-enclave-docker:
	@command -v docker >/dev/null 2>&1 || { echo "error: docker not installed"; exit 1; }
	docker volume create rsp-nix-store >/dev/null
	docker run --rm \
		-v rsp-nix-store:/nix \
		-v $(PWD):/work \
		-w /work \
		nixos/nix:latest \
		sh -c "git config --global --add safe.directory /work \
			&& nix --extra-experimental-features 'nix-command flakes' build .#enclave-$(NETWORK) --impure --out-link /tmp/result \
			&& install -m 0644 \$$(readlink -f /tmp/result)/image.eif /work/$(EIF) \
			&& install -m 0644 \$$(readlink -f /tmp/result)/pcr.json  /work/$(EIF).pcrs.json \
			&& chown $(shell id -u):$(shell id -g) /work/$(EIF) /work/$(EIF).pcrs.json"
	python3 scripts/update_expected_pcr0.py \
		$(EIF).pcrs.json \
		bin/aws-nitro-validator/src/lib.rs \
		$(NETWORK) \
		--readme README.md
	@echo "EIF: $(EIF)"
	@echo "PCR0: $$(jq -r .PCR0 $(EIF).pcrs.json)"

# ─── Release build (all networks) ────────────────────────────────────────────

NETWORKS_ALL := mainnet testnet devnet

## Build enclave + rsp-client ELF + nitro-validator ELF for every network,
## then rewrite EXPECTED_PCR0 in bin/aws-nitro-validator/src/lib.rs and the
## PCR0/vkey/version cells in README.md so they reflect the just-built
## artifacts.
##
## Order inside one network is load-bearing:
##   1. build-enclave                  → PCR0 in <eif>.pcrs.json,
##                                       writes PCR0 into lib.rs + README
##   2. build-nitro-validator-docker   → bakes that PCR0 into the vkey
##   3. build-client-docker            → independent vkey
##   4. update_readme_vkeys.py         → writes both vkeys + release version
##
## Reordering steps 1↔2 produces a stale vkey that will not match the
## PCR0 committed in §3.3 of the README.
##
## After all networks are built, check_version_bump.py enforces the
## invariant that any change to PCR0 / vkey values (relative to git HEAD
## of README.md) must be accompanied by a MAJOR version bump in the
## three Cargo.toml files. Override with SKIP_VERSION_CHECK=1 only when
## you really know what you're doing.
build-release:
	@set -e; \
	for net in $(NETWORKS_ALL); do \
		echo "=== build-release: $$net ==="; \
		$(MAKE) build-enclave NETWORK=$$net; \
		$(MAKE) build-nitro-validator-docker NETWORK=$$net; \
		$(MAKE) build-client-docker NETWORK=$$net; \
		python3 scripts/update_readme_vkeys.py \
			rsp-client-$$net.vkey \
			nitro-validator-$$net.vkey \
			README.md \
			$$net; \
	done
	@python3 scripts/check_version_bump.py
	@echo "=== build-release: done ($(NETWORKS_ALL)) ==="

## Run enclave locally (debug)
run-enclave:
	nitro-cli run-enclave \
		--eif-path $(EIF_PATH) \
		--cpu-count 6 \
		--memory 4096 \
		--enclave-cid 10

# ─── Proxy ────────────────────────────────────────────────────────────────────

build-proxy:
	RUSTFLAGS="-C target-cpu=native" cargo build --release -p proxy \
		--no-default-features --features $(NETWORK)

# ─── SP1 executor canary ──────────────────────────────────────────────────────

build-canary:
	RUSTFLAGS="-C target-cpu=native" cargo build --release -p sp1-executor-canary \
		--no-default-features --features $(NETWORK)

# ─── Run ──────────────────────────────────────────────────────────────────────

## Build and run with both backends (Nitro + SP1)
run: build-client-docker build-enclave build-proxy
	SP1_ELF_PATH=$(ELF_PATH) \
	SP1_PROVER=$(SP1_PROVER) \
	API_KEY=$(API_KEY) \
	LISTEN_ADDR=$(LISTEN_ADDR) \
	RUST_LOG=$(RUST_LOG) \
	./target/release/proxy --eif_path $(EIF_PATH)

## Build and run with SP1 only (no Nitro)
run-sp1-only: build-client-docker build-proxy
	SP1_ELF_PATH=$(ELF_PATH) \
	SP1_PROVER=network \
	API_KEY=$(API_KEY) \
	LISTEN_ADDR=$(LISTEN_ADDR) \
	RUST_LOG=$(RUST_LOG) \
	NETWORK_PRIVATE_KEY=$(NETWORK_PRIVATE_KEY) \
	./target/release/proxy

clean:
	cargo clean
	rm -f rsp-client-enclave-*.eif rsp-client-enclave-*.eif.pcrs.json \
	      rsp-client-*.elf nitro-validator-*.elf

help:
	@echo "Targets:"
	@echo "  build-client-docker           Build SP1 ELF via pinned SP1 image (no host cargo-prove)"
	@echo "  build-nitro-validator-docker  Build nitro-validator ELF via pinned SP1 image"
	@echo "  build-enclave                 Build AWS Nitro .eif via host Nix"
	@echo "  build-enclave-docker          Build AWS Nitro .eif via nixos/nix docker image (no host Nix needed)"
	@echo "  build-release                 Build enclave + client + nitro-validator for ALL networks and"
	@echo "                                rewrite PCR0/vkey/version in lib.rs + README.md in place"
	@echo "  build-proxy                   Build proxy binary"
	@echo "  run                           Build and run with Nitro + SP1"
	@echo "  run-sp1-only                  Build and run with SP1 only (no Nitro)"
	@echo "  run-enclave                   Run enclave in debug mode"
	@echo "  compose-build                 Build ELFs + docker images for compose stack"
	@echo "  compose-up                    Start proxy + witness-orchestrator in background"
	@echo "  compose-down                  Stop the compose stack (volumes preserved)"
	@echo "  compose-logs                  Tail compose logs"
	@echo "  compose-build-canary          Build canary image (opt-in via --profile canary)"
	@echo "  compose-up-canary             Start canary container (independent of prod stack)"
	@echo "  compose-down-canary           Stop and remove canary container only"
	@echo "  compose-logs-canary           Tail canary logs"
	@echo "  clean                         Remove build artifacts"
	@echo ""
	@echo "Overrides:"
	@echo "  NETWORK=$(NETWORK)            (mainnet | testnet | devnet)"
	@echo "  EIF_PATH=$(EIF_PATH)"
	@echo "  ELF_PATH=$(ELF_PATH)"
	@echo "  API_KEY=$(API_KEY)"
	@echo "  LISTEN_ADDR=$(LISTEN_ADDR)"
	@echo "  SP1_PROVER=$(SP1_PROVER)"
	@echo ""
	@echo "Examples:"
	@echo "  make build-client-docker                    # mainnet (default)"
	@echo "  make build-client-docker NETWORK=testnet    # testnet"
	@echo "  make build-enclave NETWORK=devnet           # devnet"

# ─── Genesis pre-download (for reproducible docker builds) ───────────────────

GENESIS_CACHE_DIR := .docker-cache/genesis

## Pre-download genesis.json.gz for all networks into build context.
## crates/primitives/build.rs iterates all three networks regardless of active
## feature, so we must pre-download all three — otherwise cargo build inside
## docker would pull from GitHub at compile time.
download-genesis-cache:
	@mkdir -p $(GENESIS_CACHE_DIR)
	@set -e; \
	for spec in \
		"v1.0.0:genesis-mainnet-v1.0.0.json.gz" \
		"v0.3.4-dev:genesis-v0.3.4-dev.json.gz" \
		"v0.5.7:genesis-v0.5.7.json.gz"; do \
		tag=$$(echo $$spec | cut -d: -f1); \
		name=$$(echo $$spec | cut -d: -f2); \
		path="$(GENESIS_CACHE_DIR)/$$name"; \
		if [ ! -f "$$path" ]; then \
			echo "Downloading $$name..."; \
			curl -fsSL -o "$$path.tmp" \
				"https://github.com/fluentlabs-xyz/fluentbase/releases/download/$$tag/$$name" \
				&& mv "$$path.tmp" "$$path"; \
		else \
			echo "Cached: $$name"; \
		fi; \
	done

# ─── Docker Compose ───────────────────────────────────────────────────────────

## Build docker images for the compose stack (one-shot). Both the sp1-client
## and nitro-validator ELFs are now compiled inside the Dockerfile using the
## pinned `ghcr.io/succinctlabs/sp1` image, so the host does not need
## `cargo-prove` / `sp1up`. ELFs stay inside the image layers and are never
## written to the repo root.
##
## Exports DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1 so `docker-compose` v1
## routes through BuildKit (needed for --mount=type=cache in Dockerfile).
compose-build: download-genesis-cache build-client-docker build-nitro-validator-docker
	DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1 \
		NETWORK=$(NETWORK) $(DOCKER_COMPOSE) build

## Start the compose stack in the background.
compose-up:
	NETWORK=$(NETWORK) $(DOCKER_COMPOSE) up -d

## Stop and remove the compose stack (volumes preserved).
compose-down:
	$(DOCKER_COMPOSE) down

## Tail compose logs.
compose-logs:
	$(DOCKER_COMPOSE) logs -f --tail=200

# ─── Docker Compose — canary profile ──────────────────────────────────────────
# All four targets gate on `--profile canary`; without the flag,
# `docker compose` silently skips services with `profiles:` clauses
# (image not built / container not started, no error). Each target is
# scoped to the `sp1-executor-canary` service so canary lifecycle is
# independent of the production proxy + orchestrator stack.

## Build canary image (opt-in). Reuses the same genesis cache + ELF
## prerequisites as `compose-build`.
compose-build-canary:
		DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1 \
		NETWORK=$(NETWORK) $(DOCKER_COMPOSE) --profile canary build sp1-executor-canary

## Start the canary container in the background (does not affect prod stack).
compose-up-canary:
	NETWORK=$(NETWORK) $(DOCKER_COMPOSE) --profile canary up -d sp1-executor-canary

## Stop and remove only the canary container (volumes preserved).
compose-down-canary:
	$(DOCKER_COMPOSE) --profile canary stop sp1-executor-canary
	$(DOCKER_COMPOSE) --profile canary rm -f sp1-executor-canary

## Tail canary logs.
compose-logs-canary:
	$(DOCKER_COMPOSE) logs -f --tail=200 sp1-executor-canary