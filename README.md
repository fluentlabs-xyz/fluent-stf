# Fluent RSP: Technical Architecture and Security Model

## 1. Introduction: A Hybrid Optimistic Rollup

Blockchain scaling (L2 rollups) has long been constrained by a trilemma: **throughput**, **L1 verification cost**, and **security (trustlessness)**.
* *Pure ZK-Rollups* are mathematically rigorous, but generating a ZK proof for every transaction is computationally prohibitive and expensive.
* *Pure TEE-Rollups* (built on enclaves) deliver extraordinary throughput, but on-chain certificate verification is too gas-heavy to be practical.

**Fluent RSP (Remote State Processor)** introduces a hybrid architecture — an **optimistic rollup with TEE preconfirmations and ZK dispute resolution**.
Hardware enclaves (AWS Nitro Enclaves) execute the State Transition Function (STF) at near-native speed, while ZK technology (SP1 zkVM) serves exclusively as the *supreme cryptographic arbiter* when disputes arise (Fault Proofs).

---

## 2. Batch Lifecycle (State Machine)

Every transaction batch in the L1 smart contract progresses through a strict sequence of states. Security is enforced by strict adherence to timing at each step:

1. **`Committed`**: The sequencer publishes the state commitment (the batch root).
2. **`Submitted`**: The sequencer publishes the EIP-4844 blob-hash array, anchoring the batch's transaction data on L1.
3. **`Preconfirmed`**: The attested enclave verifies the state and produces an ECDSA signature. The batch is considered preconfirmed.
4. **`Challenged` (optional)**: Any participant may dispute a specific block. The batch is frozen until the dispute is mathematically resolved via SP1.
5. **`Finalized`**: The batch becomes irreversible once the finality window elapses.

---

## 3. Root of Trust: PCR0 and Key Isolation

In TEE-based systems, the smart contract does not trust the server operator. Trust is rooted in the inaccessibility of the private key and in **PCR0** — the cryptographic fingerprint of the code running inside the enclave.

### 3.1 Hardware Key Isolation and HKDF Domain Separation

The sequencer's ECDSA private key **never exists on disk**. It is deterministically derived inside the enclave's RAM from two independent entropy sources, combined through HKDF:

```
seed          = NSM_entropy || KMS_decrypted_material
private_key   = HKDF-SHA256(seed, info = "fluent-rsp-signing-key-v1")
```

- **NSM_entropy** — a unique binding to the specific AWS Nitro instance (source: `/dev/nsm`).
- **KMS_decrypted_material** — an AWS-KMS-encrypted blob accessible to the enclave only through a role-bound KMS decrypt scoped to the AttestationDoc.

The AWS Nitro architecture physically blocks any access to enclave RAM from the outside (including from the host's root user), so extracting the private key is impossible. The corresponding public key is embedded in the AttestationDoc, which is signed by the AWS Nitro root key. On L1, the `NitroVerifier` contract maintains a whitelist of public keys admitted through a ZK attestation proof.

The logical security chain:
1. The smart contract accepts the public key because an SP1 ZK proof attested that PCR0 matches.
2. PCR0 guarantees that a strictly defined, immutable body of STF code is running inside the enclave.
3. That code is programmed to produce signatures **only** over correctly computed state roots (`batchRoot`).
4. Because the private key cannot be extracted or copied, **a valid signature from this key is an absolute guarantee that the STF was executed honestly and deterministically**.

### 3.2 Code–Hardware Identity

The fundamental axiom of the architecture: **Source code = PCR0**.
Bit-for-bit reproducibility is achieved through a hermetic build pipeline based on Nix Flakes and static linking. The pipeline mathematically guarantees that unchanged source always compiles to the same PCR0 hash, regardless of the developer's machine.

### 3.3 Per-Network Identities

Each network has its own set of cryptographic trust anchors. The values below are updated automatically by `scripts/update_expected_pcr0.py` (for PCR0) and `scripts/update_readme_vkeys.py` (for vkeys + release version) — both are invoked from the single `make build-release` target that builds the enclave, SP1 client, and nitro-validator ELFs for every network in sequence. The release version is read from `bin/client/Cargo.toml` and must match `bin/aws-nitro-validator/Cargo.toml`.


**mainnet**

| Anchor | Value |
|--------|-------|
| PCR0 enclave | <!-- pcr0:mainnet:begin -->`70405a4727bfc554c73278819a473ca1be4f3668e26b5d2626b01aa1d8da647220479ee16e781b266daf715686806462`<!-- pcr0:mainnet:end --> |
| nitro-validator vkey | <!-- nv-vkey:mainnet:begin -->`0x00e726560b91ff68e7e232d79536f4a8fb951f1f0197f97f7377b3f21e7e641e`<!-- nv-vkey:mainnet:end --> |
| rsp-client vkey | <!-- rsp-vkey:mainnet:begin -->`0x006d0fab3845f0b7bfb6500ec6b5e6ed71718c4a9cfee560fe35c81810cfd09b`<!-- rsp-vkey:mainnet:end --> |

**testnet**

| Anchor | Value |
|--------|-------|
| PCR0 enclave | <!-- pcr0:testnet:begin -->`570cce8611365cc80931f60a4270d3b59feea268de851e0af31fdfa67840994b4b9c8008b4d0d437032118c1da718083`<!-- pcr0:testnet:end --> |
| nitro-validator vkey | <!-- nv-vkey:testnet:begin -->`0x00de39fb519b1f08c2812681438a69ed2553b38cb7dcde16c0123f2e5ab27e8a`<!-- nv-vkey:testnet:end --> |
| rsp-client vkey | <!-- rsp-vkey:testnet:begin -->`0x0069f58fe92920245c9051ca96ef60d26ca7765b7c00e2142f5ae59ca59c1697`<!-- rsp-vkey:testnet:end --> |

**devnet**

| Anchor | Value |
|--------|-------|
| PCR0 enclave | <!-- pcr0:devnet:begin -->`05b4fbe673074417aba2b8336502c789aafb7aeb744be49b88d3e60c4451a37c2a4851ab17cab6e96d80c3c55b7feb54`<!-- pcr0:devnet:end --> |
| nitro-validator vkey | <!-- nv-vkey:devnet:begin -->`0x00a7ab91f8e4c967841276afdfb425e23425e269b44d8372d6bac7dd2c906d90`<!-- nv-vkey:devnet:end --> |
| rsp-client vkey | <!-- rsp-vkey:devnet:begin -->`0x00821acef2e484b6f40d6d0009d137ea1cfe324316e2bf094e14824284f46ad5`<!-- rsp-vkey:devnet:end --> |

Values built from release <!-- version:begin -->`v1.0.4`<!-- version:end -->. For independent verification, run `git checkout <version>` (e.g. `git checkout v1.0.4`) and follow the commands in §5.

### 3.4 Identity Injection into the ZK Circuit

The root of trust closes the loop at the moment of automated identity injection:
1. The build pipeline compiles the enclave and computes its PCR0.
2. This PCR0 is automatically injected (`scripts/update_expected_pcr0.py`) into the ZK validator source at `bin/aws-nitro-validator/src/lib.rs`, into the matching feature-gated block `#[cfg(feature = "<network>")] pub const EXPECTED_PCR0`.
3. SP1 compiles the ZK circuit, fixing a unique verification key (`vkey`) for the `nitro-validator` guest program.
4. The L1 `NitroVerifier` contract keeps this vkey pinned — swapping out the guest program (for example, removing the PCR0 check) would yield a different vkey and be rejected by the contract.

The consequence: the ZK attestation proof is cryptographically bound to a specific audited version of the code.

---

## 4. Symmetric Data Availability Verification

A critical property of the architecture: **blobs are verified inside Nitro exactly the same way as inside SP1**, modulo environment specifics. This guarantees an unbreakable link between STF execution and the real data on L1 (EIP-4844).

### 4.1 Blob Verification Inside Nitro and On-Chain Protection

The enclave is physically isolated from the external network and **does not know** which blobs the host actually published on Ethereum. It operates solely on the data the host passed over VSOCK (length-prefixed bincode: a 4-byte big-endian length prefix followed by the payload).

1. **Decompression and check**: the enclave decodes the raw canonical blob data, decompresses it (Brotli), and strictly checks block hashes against the results of STF execution.
2. **KZG commitment computation**: if the data is valid, the enclave *itself* computes KZG commitments for the blobs via `c-kzg` (C-FFI to the official Ethereum library) and derives the `versioned_hashes` from them.
3. **Signature generation**: the enclave signs the batch, embedding the computed `versioned_hashes` into the cryptographic payload. The signed digest has the shape `ecrecover(keccak256(abi.encode(L1_CHAIN_ID, NITRO_VERIFIER_ADDRESS, batchRoot, versionedHashes)))`.

**Where does the protection come from?** If a malicious host feeds the enclave correct data (and the enclave honestly produces a signature) but publishes *modified* blobs on Ethereum L1, the attack fails at the contract level. The smart contract uses the real on-chain blob hashes for the `ecrecover` call. Since the on-chain hashes will not match the ones bound inside the enclave's signature, `ecrecover` returns a random address and the contract rejects the batch.

### 4.2 Zero-Knowledge Data Availability (ZK-DA) Inside SP1

In a dispute, the off-chain prover (SP1) performs data-availability verification inside the ZK circuit.
The architecture proves the following fundamental properties:

1. **Deterministic state transition**: the prover mathematically proves that the State Transition Function executed flawlessly, step by step producing the claimed target block hash.
2. **State-to-data binding**: the program proves that the target block produced by execution is physically present in the supplied data.
3. **Cryptographic integrity (KZG)**: the prover mathematically confirms that the provided data strictly corresponds to the cryptographic commitments. Substitution or truncation of the transaction batch is impossible.
4. **Link to L1 consensus (Public Values)**: the ZK circuit publishes the EIP-4844 blob hashes derived from the proven commitments. The contract strictly verifies these values against the real hashes permanently recorded on-chain.

The SP1 guest `rsp-client` commits a flat public-values buffer:

```
parent_hash || block_hash || withdrawal_hash || deposit_hash || versioned_hashes[N]
```

(32-byte words, no ABI wrapping). The smart contract parses and checks.


---

## 5. Build Reproduction

All commands below run from the repository root. To independently verify that the values in the §3.3 tables are correct, check out the release tag shown in §3.3 (e.g. `git checkout v1.0.0`) and execute:

```sh
# Prerequisites: docker, python3, git, jq.

# Option A — reproduce a single network (inspect raw artifacts manually).
#
# NETWORK ∈ {mainnet, testnet, devnet}.
make build-enclave-docker         NETWORK=mainnet # runs nixos/nix inside Docker
make build-client-docker          NETWORK=mainnet
make build-nitro-validator-docker NETWORK=mainnet
   

jq -r .PCR0 rsp-client-enclave-mainnet.eif.pcrs.json    # must match §3.3
cat rsp-client-mainnet.vkey                             # must match §3.3
cat nitro-validator-mainnet.vkey                        # must match §3.3

# Option B — reproduce the full release (all three networks) and
# rewrite PCR0 / vkey / version cells in lib.rs + README in place, so
# `git diff` against the tagged commit must be empty if the build was
# reproducible.
make build-release
git diff --exit-code README.md bin/aws-nitro-validator/src/lib.rs
```

### 5.1 Running the Stack

Docker Compose is provided for running the full stack (proxy + witness-orchestrator):

```sh
make compose-build NETWORK=mainnet   # build ELFs + docker images
make compose-up    NETWORK=mainnet   # start in the background
```
