#![cfg_attr(not(test), warn(unused_crate_dependencies))]

// Mutually-exclusive feature guard.
#[cfg(any(
    all(feature = "mainnet", feature = "testnet"),
    all(feature = "mainnet", feature = "devnet"),
    all(feature = "testnet", feature = "devnet"),
))]
compile_error!(
    "features `mainnet`, `testnet`, and `devnet` are mutually exclusive — enable exactly one"
);

#[cfg(not(any(feature = "mainnet", feature = "testnet", feature = "devnet")))]
compile_error!("exactly one of features `mainnet`, `testnet`, `devnet` must be enabled");

// ─── Per-network constants ──────────────────────────────────────────────────
// All network-specific constants live in a single private `network` module,
// gated by exactly one feature. The contents are re-exported below so callers
// see a flat surface (`fluent_stf_primitives::BRIDGE_ADDRESS`, etc.).
//
// `NITRO_VERIFIER_ADDRESS` — domain separator used when signing batches
// inside the Nitro enclave so signatures cannot be replayed across chains
// or across different verifier deployments.
//
// `BRIDGE_*` — single source of truth for the bridge contract address +
// event topics. Consumed by both the in-zkVM executor
// (`crates/executor/client/src/executor.rs`) and the host-side blob builder
// (`crates/blob-builder`) so the two cannot drift.
//
// testnet/devnet currently mirror mainnet as a placeholder; update when the
// real deployments exist.

#[cfg(feature = "mainnet")]
mod network {
    use alloy_primitives::{address, b256, Address, B256};

    pub const FLUENT_CHAIN_ID: u64 = 25363;

    /// Chain ID of the L1 where `NitroVerifier` is deployed.
    /// Used as the first uint256 in the batch-signature digest, matching
    /// Solidity's `block.chainid` inside `NitroVerifier.verifyBatch`.
    pub const L1_CHAIN_ID: u64 = 1;

    // DPoS not yet deployed on mainnet (chain predates DPoS). `u64::MAX`
    // activation disables the in-enclave committee gate until DPoS is scheduled.
    // FIXME(phase5): set real activation/interval/staking when DPoS deploys.
    pub const DPOS_ACTIVATION_BLOCK: u64 = u64::MAX;
    pub const EPOCH_BLOCK_INTERVAL: u32 = 32;
    pub const DPOS_STAKING_ADDRESS: Address = Address::ZERO;
    pub const DPOS_CHAIN_CONFIG_ADDRESS: Address = Address::ZERO;

    pub const NITRO_VERIFIER_ADDRESS: [u8; 20] = [
        0xfd, 0xb0, 0x4b, 0x67, 0xec, 0xd8, 0x35, 0x2b, 0xa3, 0x88, 0x5f, 0x66, 0xff, 0xfd, 0xdf,
        0x1f, 0x5f, 0x25, 0x29, 0x2f,
    ];

    pub const BRIDGE_ADDRESS: Address = address!("0x9CAcf613fC29015893728563f423fD26dCdB8Ddc");
    pub const LEGACY_BRIDGE_WITHDRAWAL_TOPIC: B256 =
        b256!("0x7b397c6ce16a73396390bf270a2021417ca4d97f44e82cdce3f5eb750fd34134");
    pub const BRIDGE_WITHDRAWAL_TOPIC: B256 =
        b256!("0xd6dd852a42072c8955866b4726f03b3970da8db758c7af9a7130fcb97bf05977");
    pub const BRIDGE_ROLLBACK_TOPIC: B256 =
        b256!("0xdf7aa00ff05158efbc91b05d801c14d80f3d08daf5b13c7f066030c864be3d65");
    pub const BRIDGE_DEPOSIT_TOPIC: B256 =
        b256!("0xc5797c3a3c0e6c245576d05b8c3929881b44e1a21fdb4f1b118ede3c009683c5");
}

#[cfg(feature = "testnet")]
mod network {
    use alloy_primitives::{address, b256, Address, B256};

    pub const FLUENT_CHAIN_ID: u64 = 0x5202;

    /// Chain ID of the L1 where `NitroVerifier` is deployed (Sepolia).
    /// Used as the first uint256 in the batch-signature digest, matching
    /// Solidity's `block.chainid` inside `NitroVerifier.verifyBatch`.
    pub const L1_CHAIN_ID: u64 = 11155111;

    // DPoS not yet deployed on testnet. `u64::MAX` activation disables the
    // in-enclave committee gate until DPoS is scheduled.
    // FIXME(phase5): set real activation/interval/staking when DPoS deploys.
    pub const DPOS_ACTIVATION_BLOCK: u64 = u64::MAX;
    pub const EPOCH_BLOCK_INTERVAL: u32 = 32;
    pub const DPOS_STAKING_ADDRESS: Address = Address::ZERO;
    pub const DPOS_CHAIN_CONFIG_ADDRESS: Address = Address::ZERO;

    pub const NITRO_VERIFIER_ADDRESS: [u8; 20] = [
        0xba, 0x3d, 0x3b, 0x60, 0xb6, 0xf4, 0x62, 0xaa, 0x3f, 0xb2, 0xd6, 0x3f, 0x8b, 0x61, 0x0f,
        0xa8, 0x82, 0x5c, 0x30, 0x19,
    ];
    pub const BRIDGE_ADDRESS: Address = address!("0x9CAcf613fC29015893728563f423fD26dCdB8Ddc");
    pub const LEGACY_BRIDGE_WITHDRAWAL_TOPIC: B256 =
        b256!("0x7b397c6ce16a73396390bf270a2021417ca4d97f44e82cdce3f5eb750fd34134");
    pub const BRIDGE_WITHDRAWAL_TOPIC: B256 =
        b256!("0xd6dd852a42072c8955866b4726f03b3970da8db758c7af9a7130fcb97bf05977");
    pub const BRIDGE_ROLLBACK_TOPIC: B256 =
        b256!("0xdf7aa00ff05158efbc91b05d801c14d80f3d08daf5b13c7f066030c864be3d65");
    pub const BRIDGE_DEPOSIT_TOPIC: B256 =
        b256!("0xc5797c3a3c0e6c245576d05b8c3929881b44e1a21fdb4f1b118ede3c009683c5");
}

#[cfg(feature = "devnet")]
mod network {
    use alloy_primitives::{address, b256, Address, B256};

    pub const FLUENT_CHAIN_ID: u64 = 0x5201;

    /// Chain ID of the L1 where `NitroVerifier` is deployed (local Anvil).
    /// Used as the first uint256 in the batch-signature digest, matching
    /// Solidity's `block.chainid` inside `NitroVerifier.verifyBatch`.
    pub const L1_CHAIN_ID: u64 = 31337;

    // DPoS committee-cert geometry — genesis-frozen, shared by the enclave
    // (`bin/client`) and the host orchestrator (`crates/executor/host`) so the
    // committee read + epoch derivation cannot drift. Devnet values mirror the
    // `local-dpos-smoke` genesis-bootstrap (see `scripts/lib.sh`).
    pub const DPOS_ACTIVATION_BLOCK: u64 = 64;
    pub const EPOCH_BLOCK_INTERVAL: u32 = 32;
    pub const DPOS_STAKING_ADDRESS: Address =
        address!("0x0000000000000000000000000000000000005201");
    pub const DPOS_CHAIN_CONFIG_ADDRESS: Address =
        address!("0x0000000000000000000000000000000000005202");

    pub const NITRO_VERIFIER_ADDRESS: [u8; 20] = [
        0xba, 0x3d, 0x3b, 0x60, 0xb6, 0xf4, 0x62, 0xaa, 0x3f, 0xb2, 0xd6, 0x3f, 0x8b, 0x61, 0x0f,
        0xa8, 0x82, 0x5c, 0x30, 0x19,
    ];

    pub const BRIDGE_ADDRESS: Address = address!("0x9CAcf613fC29015893728563f423fD26dCdB8Ddc");
    pub const LEGACY_BRIDGE_WITHDRAWAL_TOPIC: B256 =
        b256!("0x7b397c6ce16a73396390bf270a2021417ca4d97f44e82cdce3f5eb750fd34134");
    pub const BRIDGE_WITHDRAWAL_TOPIC: B256 =
        b256!("0xd6dd852a42072c8955866b4726f03b3970da8db758c7af9a7130fcb97bf05977");
    pub const BRIDGE_ROLLBACK_TOPIC: B256 =
        b256!("0xdf7aa00ff05158efbc91b05d801c14d80f3d08daf5b13c7f066030c864be3d65");
    pub const BRIDGE_DEPOSIT_TOPIC: B256 =
        b256!("0xc5797c3a3c0e6c245576d05b8c3929881b44e1a21fdb4f1b118ede3c009683c5");
}

pub use network::*;

/// `NITRO_VERIFIER_ADDRESS` as an `Address` for host-side code.
pub const NITRO_VERIFIER_ADDR: alloy_primitives::Address =
    alloy_primitives::Address::new(NITRO_VERIFIER_ADDRESS);

/// Epoch index of `block_number` under the DPoS geometry — the same arithmetic
/// the on-chain `Staking` uses to bucket blocks into epochs. Saturating and
/// zero-interval-guarded so a not-yet-initialised `ChainConfig` (interval read
/// as 0 at runtime) yields epoch 0 rather than a division-by-zero panic. Single
/// source for the STF replay (`executor/client`), the host witness pass, and the
/// enclave verify so the three cannot drift.
pub const fn epoch_of_block(
    block_number: u64,
    epoch_block_interval: u32,
    dpos_activation_block: u64,
) -> u64 {
    if epoch_block_interval == 0 {
        return 0;
    }
    block_number.saturating_sub(dpos_activation_block) / epoch_block_interval as u64
}

pub mod account_proof;

#[allow(clippy::all, unused_imports)]
pub(crate) mod fluent_genesis {
    include!(concat!(env!("OUT_DIR"), "/fluent_genesis.rs"));
}

pub use fluent_genesis::chainspec as fluent_chainspec;
