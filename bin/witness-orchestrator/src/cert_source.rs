//! Consensus-RPC `consensus_getFinalization` client glue (task
//! `dpos_l1_rollup_committee_binding`, Phase 3).
//!
//! The node exposes `consensus_getFinalization(Query) -> CertifiedBlock` (merged
//! into its standard RPC). `CertifiedBlock` carries the finalized block AND its
//! finalization certificate as hex:
//!   - `certificate` = commonware-codec `Finalization` — passed to the enclave as raw bytes (the
//!     enclave decodes/verifies; we only `hex::decode` here);
//!   - `block` = the node's `SealedBlock<reth Block>` encoding. The node calls commonware
//!     `Block::encode`, but `Block::write` (`fluentbase/crates/consensus/src/block.rs:71`) just
//!     delegates to `alloy_rlp::Encodable` with no extra framing, so the bytes are plain alloy-RLP
//!     and we decode them with `alloy_rlp` — no commonware dep here. (If the node ever adds
//!     commonware framing around the RLP body, this decode must change in lockstep.)
//!
//! Vendored DTO (mirrors `fluentbase/crates/node/src/consensus_rpc/types.rs` +
//! `certified_block.rs`); vendor-now / pin-later, like the cert-verify crate.

use alloy_primitives::hex;
use alloy_provider::{network::Ethereum, Provider, RootProvider};
use reth_ethereum_primitives::Block as RethBlock;
use serde::{Deserialize, Serialize};

/// `consensus_getFinalization(Height(height))` against the node RPC (merged into
/// the standard endpoint). Errors (incl. `Missing`/`NotReady` for a
/// not-yet-finalized / not-yet-archived height) propagate — the driver treats
/// them as "not finalized yet → retry", which is the implicit finality gate.
pub async fn fetch_finalization(
    rpc: &RootProvider<Ethereum>,
    height: u64,
) -> eyre::Result<CertifiedBlock> {
    rpc.client()
        .request::<_, CertifiedBlock>("consensus_getFinalization", (Query::Height(height),))
        .await
        .map_err(|e| eyre::eyre!("consensus_getFinalization({height}): {e}"))
}

/// By-height / latest selector. Serde form is `"latest"` or `{"height": N}`
/// (mirrors the node's `Query`, `consensus_rpc/types.rs`).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Query {
    #[allow(dead_code)]
    Latest,
    Height(u64),
}

/// Wire DTO returned by `consensus_getFinalization` (mirrors the node's
/// `CertifiedBlock`: both fields hex-encoded).
#[derive(Debug, Clone, Deserialize)]
pub struct CertifiedBlock {
    pub certificate: String,
    pub block: String,
}

impl CertifiedBlock {
    /// `(cert_bytes, block)`. The cert stays raw bytes (enclave decodes it); the
    /// block is alloy-RLP-decoded into a reth block (unsealed for execution).
    pub fn into_parts(self) -> eyre::Result<(Vec<u8>, RethBlock)> {
        let cert = hex::decode(self.certificate.trim_start_matches("0x"))
            .map_err(|e| eyre::eyre!("decode certificate hex: {e}"))?;
        let block_bytes = hex::decode(self.block.trim_start_matches("0x"))
            .map_err(|e| eyre::eyre!("decode block hex: {e}"))?;
        let block = decode_block_rlp(&block_bytes)?;
        Ok((cert, block))
    }
}

/// Decode the node's RLP-encoded `SealedBlock<reth Block>` into an (unsealed)
/// reth block. The node writes `SealedBlock::encode` (alloy-RLP); we decode the
/// same and unseal for execution.
fn decode_block_rlp(bytes: &[u8]) -> eyre::Result<RethBlock> {
    use reth_primitives_traits::block::SealedBlock;
    let sealed: SealedBlock<RethBlock> = alloy_rlp::Decodable::decode(&mut &bytes[..])
        .map_err(|e| eyre::eyre!("rlp decode SealedBlock: {e}"))?;
    Ok(sealed.into_block())
}
