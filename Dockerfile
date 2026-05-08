FROM lukemathwalker/cargo-chef:latest-rust-1-bookworm AS chef
WORKDIR /app

# System dependencies. Intentionally no `apt-get upgrade` — it makes builds
# non-reproducible across days (different package versions appear over time).
RUN apt-get update && apt-get install -y --no-install-recommends \
    libclang-dev \
    pkg-config \
    protobuf-compiler \
    libprotobuf-dev \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Builds a cargo-chef plan. Copy only what chef needs to read manifests —
# avoids invalidating recipe.json when unrelated files (ELFs, bin/client,
# bin/aws-nitro-validator) change.
FROM chef AS planner

COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY bin/proxy/ bin/proxy/
COPY bin/witness-orchestrator/ bin/witness-orchestrator/
COPY bin/sp1-executor-canary/ bin/sp1-executor-canary/
RUN cargo chef prepare --recipe-path recipe.json

###############################################################################
#                                                                             #
#                              Combined Builder                               #
#                                                                             #
# Compiles proxy + witness-orchestrator in one cargo invocation so that       #
# shared workspace crates (rsp-host-executor, fluent-stf-primitives, etc)     #
# are compiled once, not per-binary.                                          #
###############################################################################
FROM chef AS builder

ARG NETWORK=mainnet

COPY --from=planner /app/recipe.json recipe.json

# Pre-downloaded genesis cache. crates/primitives/build.rs resolves its cache
# dir via directories::ProjectDirs — on Linux with HOME=/root it lands here.
# Without this COPY, build.rs would HTTPS-pull three genesis.json.gz files
# from GitHub on every cold build.
COPY .docker-cache/genesis /root/.cache/fluent/genesis

# Cook deps with the SAME feature flags as the final cargo build, otherwise
# feature unification forces partial recompilation during the real build.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo chef cook --profile release --recipe-path recipe.json \
        --no-default-features --features "${NETWORK}" \
        -p proxy -p witness-orchestrator-bin -p sp1-executor-canary

# Application source. trusted_setup.txt is pulled via include_bytes! in
# bin/proxy/src/main.rs; the file ships with bin/client but is read at
# compile time from here.
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY bin/proxy/ bin/proxy/
COPY bin/witness-orchestrator/ bin/witness-orchestrator/
COPY bin/sp1-executor-canary/ bin/sp1-executor-canary/
COPY bin/client/trusted_setup.txt bin/client/trusted_setup.txt

# Single cargo build — compiles both binaries against a unified dep graph.
# The `cp` must run inside the same RUN as cargo build because /app/target
# is a cache mount (not a layer-visible directory).
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --profile release --locked \
        -p proxy -p witness-orchestrator-bin -p sp1-executor-canary \
        --no-default-features --features "${NETWORK}" \
    && cp /app/target/release/proxy /app/proxy \
    && cp /app/target/release/witness-orchestrator /app/witness-orchestrator \
    && cp /app/target/release/sp1-executor-canary /app/sp1-executor-canary

###############################################################################
#                                                                             #
#                            SP1 Toolchain Base                               #
#                                                                             #
# Debian + rust + sp1up-installed cargo-prove and succinct toolchain. Shared  #
# base for both ELF builders so `cargo prove build` and `cargo prove vkey`    #
# are available without installing anything on the host.                      #
###############################################################################
FROM rust:1.94-bookworm AS sp1-tools

ARG SP1_VERSION=v6.1.0

# curl/git: needed by the sp1up installer. clang/libssl/pkg-config: needed by
# some SP1-program build scripts (k256, etc).
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates git clang libclang-dev libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/root/.sp1/bin:${PATH}"

# sp1up downloads the cargo-prove binary + the succinct rust toolchain (linked
# into rustup as `succinct`). Both pinned to ${SP1_VERSION}, so reproducibility
# is the same as pinning a docker image tag.
RUN curl -sSL https://sp1.succinct.xyz | bash \
    && sp1up --version ${SP1_VERSION}

###############################################################################
#                                                                             #
#                          SP1 Client ELF Builder                             #
#                                                                             #
# Runs `cargo prove build` (handles RUSTFLAGS / --cfg getrandom_backend /     #
# RISC-V target selection internally) and then `cargo prove vkey` to produce  #
# a vkey file alongside the ELF.                                              #
###############################################################################
FROM sp1-tools AS sp1-client-elf-builder

ARG NETWORK=mainnet

WORKDIR /app

# Genesis cache — crates/primitives/build.rs resolves its cache dir via
# directories::ProjectDirs (Linux: $HOME/.cache/<name>). Without this COPY,
# build.rs HTTPS-fetches on every build.
COPY .docker-cache/genesis /root/.cache/fluent/genesis

# bin/client has its own [workspace], but its path deps under crates/ inherit
# `edition.workspace = true` from the REPO-ROOT Cargo.toml — cargo walks up
# from each path dep to find a workspace for inheritance. So the root
# Cargo.toml / Cargo.lock are required, and every member listed in its
# `[workspace].members` must exist on disk (cargo validates the list before
# resolving). We therefore also ship bin/proxy and bin/witness-orchestrator
# manifests — they're never compiled here, just parsed.
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY bin/proxy/ bin/proxy/
COPY bin/witness-orchestrator/ bin/witness-orchestrator/
COPY bin/client/ bin/client/

# `cargo prove vkey --elf` fails ("setup task failed") on externally-built
# ELFs in SP1 v6.1, so we derive the vkey via `--program` from the crate
# directory instead. The second invocation re-uses the compile cache from the
# first, so only the setup step runs. The `mv` / write must live in the same
# RUN because target/ is a cache mount.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/bin/client/target \
    cd bin/client \
    && cargo prove build \
        --elf-name sp1-client.elf \
        --locked \
        --output-directory /out \
        --no-default-features \
        --features "sp1 ${NETWORK}" \
    && cargo prove vkey --program rsp-client \
        | awk '/^0x/{print $1}' > /out/sp1-client.vkey

###############################################################################
# SP1 Client ELF Export Stage
#
# Exists only to let `docker build --target sp1-client-elf-export --output
# type=local,dest=.` extract the ELF + vkey onto the host with the network-
# tagged filenames the Makefile expects. `FROM scratch` keeps the export tree
# empty so BuildKit writes exactly the files we copy in.
###############################################################################
FROM scratch AS sp1-client-elf-export

ARG NETWORK=mainnet

COPY --from=sp1-client-elf-builder /out/sp1-client.elf  /rsp-client-${NETWORK}.elf
COPY --from=sp1-client-elf-builder /out/sp1-client.vkey /rsp-client-${NETWORK}.vkey

###############################################################################
#                                                                             #
#                       Nitro-Validator ELF Builder                           #
#                                                                             #
# Standalone SP1 program (its own workspace, no crates/ path deps).           #
###############################################################################
FROM sp1-tools AS nitro-validator-elf-builder

ARG NETWORK=mainnet

WORKDIR /app

COPY bin/aws-nitro-validator/ bin/aws-nitro-validator/

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/bin/aws-nitro-validator/target \
    cd bin/aws-nitro-validator \
    && cargo prove build \
        --elf-name nitro-validator.elf \
        --locked \
        --output-directory /out \
        --no-default-features \
        --features "${NETWORK}" \
    && cargo prove vkey --program nitro-validator \
        | awk '/^0x/{print $1}' > /out/nitro-validator.vkey

###############################################################################
# Nitro-Validator ELF Export Stage (see SP1 client export stage above)
###############################################################################
FROM scratch AS nitro-validator-elf-export

ARG NETWORK=mainnet

COPY --from=nitro-validator-elf-builder /out/nitro-validator.elf  /nitro-validator-${NETWORK}.elf
COPY --from=nitro-validator-elf-builder /out/nitro-validator.vkey /nitro-validator-${NETWORK}.vkey

###############################################################################
#                                                                             #
#                            Proxy Runtime Prep                               #
#                                                                             #
###############################################################################
# Distroless has no shell / mkdir / chown, so we prepare writable directories
# with correct ownership in a throwaway debian stage and COPY --from=prep them.
# nonroot in distroless is UID 65532.
FROM debian:bookworm-slim AS rsp-proxy-prep
RUN mkdir -p /out/var/lib/proxy /out/opt/elfs && \
    chown -R 65532:65532 /out/var/lib/proxy

###############################################################################
#                                                                             #
#                              Proxy Runtime                                  #
#                                                                             #
###############################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS rsp-proxy

ARG NETWORK=mainnet

# busybox (static) for the TCP healthcheck — distroless has no shell/nc.
# ~1MB overhead, single binary, musl-static.
COPY --from=busybox:1.37.0-musl /bin/busybox /busybox

COPY --from=rsp-proxy-prep --chown=65532:65532 /out/var/lib/proxy /var/lib/proxy
COPY --from=rsp-proxy-prep /out/opt/elfs /opt/elfs

COPY rsp-client-${NETWORK}.elf       /opt/elfs/sp1-client.elf
COPY nitro-validator-${NETWORK}.elf  /opt/elfs/nitro-validator.elf

COPY --from=builder /app/proxy /usr/local/bin/proxy

ENV SP1_ELF_PATH=/opt/elfs/sp1-client.elf \
    NITRO_VALIDATOR_ELF_PATH=/opt/elfs/nitro-validator.elf \
    PROXY_DB_PATH=/var/lib/proxy/proxy.db \
    HOME=/var/lib/proxy

USER nonroot:nonroot
WORKDIR /var/lib/proxy

ENTRYPOINT ["/usr/local/bin/proxy"]

###############################################################################
#                                                                             #
#                      Witness-Orchestrator Runtime Prep                      #
#                                                                             #
###############################################################################
FROM debian:bookworm-slim AS rsp-witness-orchestrator-prep
RUN mkdir -p /out/var/lib/witness && \
    chown -R 65532:65532 /out/var/lib/witness

###############################################################################
#                                                                             #
#                       Witness-Orchestrator Runtime                          #
#                                                                             #
###############################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS rsp-witness-orchestrator

COPY --from=busybox:1.37.0-musl /bin/busybox /busybox

COPY --from=rsp-witness-orchestrator-prep --chown=65532:65532 /out/var/lib/witness /var/lib/witness

COPY --from=builder /app/witness-orchestrator /usr/local/bin/witness-orchestrator

ENV FLUENT_DB_PATH=/var/lib/witness/witness_courier.db \
    HOME=/var/lib/witness

USER nonroot:nonroot
WORKDIR /var/lib/witness

ENTRYPOINT ["/usr/local/bin/witness-orchestrator"]

###############################################################################
#                                                                             #
#                          SP1 Executor Canary Prep                           #
#                                                                             #
###############################################################################
FROM debian:bookworm-slim AS rsp-canary-prep
RUN mkdir -p /out/var/lib/canary /out/opt/elfs && \
    chown -R 65532:65532 /out/var/lib/canary

###############################################################################
#                                                                             #
#                            SP1 Executor Canary                              #
#                                                                             #
###############################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS rsp-canary

ARG NETWORK=mainnet

# busybox (static) for the /metrics HTTP healthcheck — distroless has no
# shell/wget. ~1MB overhead, single binary, musl-static.
COPY --from=busybox:1.37.0-musl /bin/busybox /busybox

COPY --from=rsp-canary-prep --chown=65532:65532 /out/var/lib/canary /var/lib/canary
COPY --from=rsp-canary-prep /out/opt/elfs /opt/elfs

# Same rsp-client ELF the proxy bakes in: canary's whole point is to
# re-execute production blocks through the **identical** pinned ELF
# that proxy signs preconfirmations with. If these two artifacts
# diverge the canary stops being a canary.
COPY rsp-client-${NETWORK}.elf /opt/elfs/sp1-client.elf

COPY --from=builder /app/sp1-executor-canary /usr/local/bin/sp1-executor-canary

ENV SP1_ELF_PATH=/opt/elfs/sp1-client.elf \
    HOME=/var/lib/canary

USER nonroot:nonroot
WORKDIR /var/lib/canary

ENTRYPOINT ["/usr/local/bin/sp1-executor-canary"]