{
  description = "Fluent RSP client — reproducible AWS Nitro EIF via monzo/aws-nitro-util";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";

    flake-utils.url = "github:numtide/flake-utils";

    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";

    crane.url = "github:ipetkov/crane";

    # nitro-util's buildGoModule usage predates nixpkgs 25.05's structured-env
    # change (CGO_ENABLED must now live in `env`, not derivation args).
    # Let it pull its own vendored nixpkgs to avoid the attribute conflict.
    nitro-util.url = "github:monzo/aws-nitro-util";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, crane, nitro-util }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

        nitro = nitro-util.lib.${system};

        # Rust toolchain with x86_64-linux-musl target for static enclave binary.
        rustToolchain = pkgs.rust-bin.stable."1.94.1".default.override {
          targets = [ "x86_64-unknown-linux-musl" ];
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        # Pre-fetched genesis blobs for crates/primitives/build.rs.
        # build.rs iterates all three networks regardless of feature, so all
        # three must be present or the build fails trying to hit the network.
        genesisMainnet = pkgs.fetchurl {
          url = "https://github.com/fluentlabs-xyz/fluentbase/releases/download/v1.0.0/genesis-mainnet-v1.0.0.json.gz";
          sha256 = "72cb4b3b7b15de952bd1094281a1f2430cb711bc473a0520f92aa3e2b1bdb643";
        };
        genesisTestnet = pkgs.fetchurl {
          url = "https://github.com/fluentlabs-xyz/fluentbase/releases/download/v0.3.4-dev/genesis-v0.3.4-dev.json.gz";
          sha256 = "8cd30358c5664375e6739bc48302445e7ee10fd0158bedb788505e5c590983bd";
        };

        # Crane vendors git deps per-commit (not per-name), so duplicate-name
        # crates like ecdsa-0.16.9 (appearing as both registry + git in the
        # same Cargo.lock) don't collide. However, when crane fetches a crate
        # from a git workspace, it vendors ONLY the crate's subdir — stripping
        # the workspace root's Cargo.toml. This breaks `readme.workspace =
        # true` inheritance (as used by op-revm). We patch the vendored
        # op-revm Cargo.toml to inline a concrete readme value.
        rawCargoVendor = craneLib.vendorCargoDeps {
          cargoLock = ./bin/client/Cargo.lock;
        };
        cargoVendorDir = pkgs.runCommand "rsp-client-vendor-patched" { } ''
          cp -rL --no-preserve=mode,ownership ${rawCargoVendor} $out
          # config.toml has absolute paths pointing back to the source derivation;
          # rewrite them to point at our patched copy at $out.
          sed -i "s|${rawCargoVendor}|$out|g" $out/config.toml
          # Several revm-rwasm crates (op-revm, revm-bytecode, ...) use
          # `readme.workspace = true`, but the workspace root doesn't define
          # workspace.package.readme at all — cargo tolerates this at
          # workspace level but fails when only the crate is vendored.
          # Rewrite every offending line to a concrete readme value.
          find $out -name Cargo.toml -print0 | xargs -0 \
            sed -i 's|^readme\.workspace = true|readme = "README.md"|'
        '';

        # Build rsp-client for one network feature → static musl ELF via crane.
        # Using crane (not buildRustPackage) because the latter's
        # replace-workspace-values postPatch script crashes on op-revm's
        # `readme.workspace = true` with KeyError: 'readme'.
        mkRspClient = network:
          craneLib.buildPackage {
            pname = "rsp-client-${network}";
            version = "0.1.0";

            # bin/client is a standalone crate but path-depends on ../../crates/*,
            # so the source must include both. sourceRoot cd's into bin/client
            # for cargo; the sibling crates/ stays reachable via relative paths.
            #
            # The filter is scoped to bin/client + crates/ only — unrelated
            # subtrees (bin/aws-nitro-validator, bin/proxy, bin/witness-*,
            # scripts/, Makefile, Dockerfile, README*.md, docs/) MUST NOT
            # influence the source hash, otherwise mutating their files
            # (e.g. scripts/update_expected_pcr0.py rewriting EXPECTED_PCR0
            # in aws-nitro-validator/src/lib.rs after each build, or
            # scripts/update_readme_vkeys.py rewriting README.md after
            # each ELF build) would cascade into a different PCR0 on every
            # rebuild. This filter is an ALLOWLIST: anything not explicitly
            # matched by `inWanted` below is excluded. Do NOT broaden
            # `inWanted` without understanding this contract — in particular,
            # never add README.md, scripts/, or any of the host-side
            # crates here.
            src = pkgs.lib.cleanSourceWith {
              src = ./.;
              filter = path: type:
                let
                  root = toString ./.;
                  rel = pkgs.lib.removePrefix (root + "/") (toString path);
                  inWanted =
                    rel == "bin/client" || pkgs.lib.hasPrefix "bin/client/" rel
                    || rel == "crates"   || pkgs.lib.hasPrefix "crates/" rel
                    || rel == "Cargo.toml" || rel == "Cargo.lock";
                  isAncestor = rel == "" || rel == "bin";
                in
                  (inWanted || isAncestor)
                  && (type == "directory"
                      || craneLib.filterCargoSources path type
                      || builtins.match ".*/bin/client/trusted_setup\\.txt$" path != null);
            };
            sourceRoot = "source/bin/client";

            cargoToml = ./bin/client/Cargo.toml;
            cargoLock = ./bin/client/Cargo.lock;
            inherit cargoVendorDir;

            cargoExtraArgs = "--locked --no-default-features --features nitro,${network}";

            nativeBuildInputs = [ rustToolchain ];

            CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
            CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = "${pkgs.pkgsStatic.stdenv.cc}/bin/${pkgs.pkgsStatic.stdenv.cc.targetPrefix}cc";

            # Pre-populate genesis cache so build.rs skips network download.
            # directories::ProjectDirs::from(_, _, "fluent").cache_dir()
            # resolves to $HOME/.cache/fluent on Linux.
            preBuild = ''
              export HOME="$TMPDIR/home"
              # Canonicalize the build tree location so rustc/LLVM see the
              # same absolute paths regardless of how nix invoked us.
              # Sandboxed host nix uses $NIX_BUILD_TOP=/build; unsandboxed
              # nix-in-docker uses /nix/var/nix/builds/nix-N-<pid>. Even with
              # --remap-path-prefix, rustc's SVH/metadata hash and LLVM's
              # monomorphization ordering depend on input paths, so differing
              # $NIX_BUILD_TOP leads to different binary layout → different
              # PCR0. Copy the source tree to a fixed path under /tmp and
              # continue the build from there.
              CANONICAL_BUILD=/tmp/rsp-canonical-build
              if [ "$PWD" != "$CANONICAL_BUILD/source/bin/client" ]; then
                rm -rf "$CANONICAL_BUILD"
                mkdir -p "$CANONICAL_BUILD"
                # Preserve mode (nix store entries are r-x/r--); just add user
                # write so cargo can create target/ and write build artifacts.
                # --no-preserve=ownership only, to avoid chown failures when
                # the builder uid differs from the file owner in the sandbox.
                cp -rL --no-preserve=ownership "$NIX_BUILD_TOP/." "$CANONICAL_BUILD/"
                chmod -R u+w "$CANONICAL_BUILD"
                cd "$CANONICAL_BUILD/source/bin/client"
              fi
              # Also remap build paths for defense in depth (covers file!(),
              # panic strings, env!("CARGO_MANIFEST_DIR"), etc).
              export RUSTFLAGS="--remap-path-prefix=$CANONICAL_BUILD=src"
              mkdir -p "$HOME/.cache/fluent/genesis"
              install -m 0644 ${genesisMainnet} "$HOME/.cache/fluent/genesis/genesis-mainnet-v1.0.0.json.gz"
              install -m 0644 ${genesisTestnet} "$HOME/.cache/fluent/genesis/genesis-v0.3.4-dev.json.gz"
            '';

            doCheck = false;

            installPhaseCommand = ''
              mkdir -p $out/bin
              install -m 0755 \
                target/x86_64-unknown-linux-musl/release/rsp-client \
                $out/bin/rsp-client
            '';
          };

        mkEnclave = network:
          let
            client = mkRspClient network;
          in
          nitro.buildEif {
            name = "rsp-client-enclave-${network}";
            arch = "x86_64";

            kernel = nitro.blobs.x86_64.kernel;
            kernelConfig = nitro.blobs.x86_64.kernelConfig;
            nsmKo = nitro.blobs.x86_64.nsmKo;
            cmdline = builtins.readFile nitro.blobs.x86_64.cmdLine;

            copyToRoot = pkgs.buildEnv {
              name = "rsp-enclave-root";
              paths = [ client ];
              pathsToLink = [ "/bin" ];
            };

            entrypoint = "/bin/rsp-client";
            env = "";
          };
      in
      {
        packages = {
          rsp-client-mainnet = mkRspClient "mainnet";
          rsp-client-testnet = mkRspClient "testnet";

          enclave-mainnet = mkEnclave "mainnet";
          enclave-testnet = mkEnclave "testnet";

          default = mkEnclave "mainnet";
        };

        devShells.default = pkgs.mkShell {
          buildInputs = [
            rustToolchain
            pkgs.pkgsStatic.stdenv.cc
          ];
        };
      });
}
