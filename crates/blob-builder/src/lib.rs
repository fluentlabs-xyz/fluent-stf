//! Build EIP-4844 blobs from L2 blocks fetched via RPC.
//!
//! Wire format (matches Go sequencer `blob.go`):
//!
//!   byte 0    : version (0x01)
//!   bytes 1.. : brotli(rlp([ [headerRLP, [txEnv₀, txEnv₁, ...]], ... ]))
//!
//! headerRLP is the already-encoded RLP of the block header, inserted
//! verbatim (Go's rlp.RawValue). Each txEnv is the EIP-2718 envelope
//! bytes (tx.MarshalBinary / encoded_2718).
//!
//! Uses `brotlic` (C reference libbrotli) for byte-identity with the Go
//! sequencer. The pure-Rust `brotli` crate produces different output on real
//! transaction data and would break the SP1 verifier's versioned-hash check.

pub mod kzg_input;
pub use kzg_input::prepare_blob_verification_input;

use std::io::Write;

use alloy_consensus::{Block, TxEnvelope};
use alloy_eips::Encodable2718;
use alloy_provider::{Provider, RootProvider};
use alloy_rlp::{Encodable, Header as RlpHeader};
use brotlic::{BrotliEncoderOptions, CompressorWriter, Quality, WindowSize};
use eyre::{eyre, Result};
use tracing::info;

/// EIP-4844 blob size: 4096 field elements × 32 bytes = 131072 bytes.
const BYTES_PER_BLOB: usize = 131_072;

const BYTES_PER_FIELD_ELEMENT: usize = 31;
const FIELD_ELEMENTS_PER_BLOB: usize = BYTES_PER_BLOB / 32;
const MAX_RAW_BYTES_PER_BLOB: usize = FIELD_ELEMENTS_PER_BLOB * BYTES_PER_FIELD_ELEMENT;

const FETCH_BATCH_SIZE: u64 = 100;

/// Blob format version byte — cleartext prefix of the raw blob stream.
/// Placed outside brotli so decoders can dispatch without decompression.
const BLOB_FORMAT_VERSION: u8 = 0x01;

/// Pre-encoded block payload shaped for [`build_blobs_from_fetched`]:
/// the canonical RLP-encoded header bytes and per-tx EIP-2718 envelope
/// bytes.
#[derive(Debug)]
pub struct FetchedBlock {
    pub header_rlp: Vec<u8>,
    pub tx_envelopes: Vec<Vec<u8>>,
}

/// Fetch L2 blocks and build canonical EIP-4844 blobs.
///
/// Returns `Vec<Vec<u8>>` where each inner Vec is exactly BYTES_PER_BLOB (131072) bytes.
pub async fn build_blobs_from_l2(
    provider: &RootProvider,
    from_block: u64,
    to_block: u64,
) -> Result<Vec<Vec<u8>>> {
    let blocks = fetch_blocks(provider, from_block, to_block).await?;
    let blobs = build_blobs_from_fetched(blocks)?;
    info!(from_block, to_block, num_blobs = blobs.len(), "Built blobs from L2 RPC");
    Ok(blobs)
}

/// Build canonical EIP-4844 blobs from already-fetched block data.
///
/// Pipeline: RLP encode → brotli (quality=6, lgwin=22, mode=Generic via
/// `brotlic`) → version-byte prefix → chunk into BYTES_PER_BLOB-length
/// canonical buffers. Bit-stable on this exact input shape.
pub fn build_blobs_from_fetched(blocks: Vec<FetchedBlock>) -> Result<Vec<Vec<u8>>> {
    let rlp_payload = encode_batch_payload(&blocks);
    let compressed = brotli_compress(&rlp_payload)?;

    // Prepend version byte outside brotli.
    let mut stream = Vec::with_capacity(1 + compressed.len());
    stream.push(BLOB_FORMAT_VERSION);
    stream.extend_from_slice(&compressed);

    stream.chunks(MAX_RAW_BYTES_PER_BLOB).map(build_single_blob).collect()
}

/// Concurrent block fetch batched by `FETCH_BATCH_SIZE`. Each block is
/// converted to headerRLP + tx envelopes matching Go's ProcessedBlock.
async fn fetch_blocks(
    provider: &RootProvider,
    from_block: u64,
    to_block: u64,
) -> Result<Vec<FetchedBlock>> {
    let total: usize = (to_block - from_block + 1) as usize;
    let mut result: Vec<FetchedBlock> = Vec::with_capacity(total);
    let mut current = from_block;

    while current <= to_block {
        let batch_end = (current + FETCH_BATCH_SIZE - 1).min(to_block);

        let futs = (current..=batch_end).map(|bn| {
            let provider = provider.clone();
            async move {
                let rpc_block = provider
                    .get_block_by_number(bn.into())
                    .full()
                    .await
                    .map_err(|e| eyre!("get_block_by_number({bn}) failed: {e}"))?
                    .ok_or_else(|| eyre!("L2 block {bn} not found"))?;

                let consensus: Block<TxEnvelope> =
                    rpc_block.map_transactions(TxEnvelope::from).into_consensus();

                let header_rlp = alloy_rlp::encode(&consensus.header);
                let tx_envelopes: Vec<Vec<u8>> =
                    consensus.body.transactions.iter().map(|tx| tx.encoded_2718()).collect();

                Ok::<(u64, FetchedBlock), eyre::Report>((
                    bn,
                    FetchedBlock { header_rlp, tx_envelopes },
                ))
            }
        });

        let mut batch = futures::future::try_join_all(futs).await?;
        batch.sort_by_key(|(bn, _)| *bn);
        for (_, block) in batch {
            result.push(block);
        }
        current = batch_end + 1;
    }

    Ok(result)
}

/// Encode blocks into the Go-compatible RLP batch payload.
///
/// Produces `rlp([ [headerRLP, [txEnv₀, ...]], ... ])` — matching
/// Go's `EncodeBatchPayload` with `blobBlock { rlp.RawValue, [][]byte }`.
fn encode_batch_payload(blocks: &[FetchedBlock]) -> Vec<u8> {
    // Compute total payload length for the outer list.
    let mut outer_payload_len = 0;
    for block in blocks {
        let txs_payload_len: usize =
            block.tx_envelopes.iter().map(|tx| tx.as_slice().length()).sum();
        let txs_list_len =
            RlpHeader { list: true, payload_length: txs_payload_len }.length() + txs_payload_len;
        let block_payload_len = block.header_rlp.len() + txs_list_len;
        let block_total_len = RlpHeader { list: true, payload_length: block_payload_len }.length() +
            block_payload_len;
        outer_payload_len += block_total_len;
    }

    let mut out = Vec::with_capacity(
        RlpHeader { list: true, payload_length: outer_payload_len }.length() + outer_payload_len,
    );

    // Outer list header.
    RlpHeader { list: true, payload_length: outer_payload_len }.encode(&mut out);

    for block in blocks {
        // Per-block list: [headerRLP, [txEnvelopes...]]
        let txs_payload_len: usize =
            block.tx_envelopes.iter().map(|tx| tx.as_slice().length()).sum();
        let txs_list_len =
            RlpHeader { list: true, payload_length: txs_payload_len }.length() + txs_payload_len;
        let block_payload_len = block.header_rlp.len() + txs_list_len;

        // Block list header.
        RlpHeader { list: true, payload_length: block_payload_len }.encode(&mut out);

        // HeaderRLP — inserted verbatim (Go's rlp.RawValue semantics).
        out.extend_from_slice(&block.header_rlp);

        // Txs list.
        RlpHeader { list: true, payload_length: txs_payload_len }.encode(&mut out);
        for tx in &block.tx_envelopes {
            tx.as_slice().encode(&mut out);
        }
    }

    out
}

/// Brotli compress via C reference libbrotli (quality=6, lgwin=22, mode=Generic).
///
/// Uses `brotlic` which compiles the C reference libbrotli from source, guaranteeing
/// byte-identical output with the Go sequencer (andybalholm/brotli is a c2go
/// translation of the same C reference). The pure-Rust brotli crate produces
/// different output on real transaction data.
fn brotli_compress(data: &[u8]) -> Result<Vec<u8>> {
    let encoder = BrotliEncoderOptions::new()
        .quality(Quality::new(6).map_err(|e| eyre!("invalid quality: {e}"))?)
        .window_size(WindowSize::new(22).map_err(|e| eyre!("invalid window size: {e}"))?)
        .build()
        .map_err(|e| eyre!("encoder build failed: {e}"))?;

    let mut writer = CompressorWriter::with_encoder(encoder, Vec::new());
    writer.write_all(data).map_err(|e| eyre!("brotli compress failed: {e}"))?;
    let compressed = writer.into_inner().map_err(|e| eyre!("brotli finalize failed: {e}"))?;
    Ok(compressed)
}

/// Canonicalize raw bytes and build a blob buffer.
fn build_single_blob(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() > MAX_RAW_BYTES_PER_BLOB {
        return Err(eyre!(
            "data ({} bytes) exceeds blob capacity ({MAX_RAW_BYTES_PER_BLOB})",
            raw.len()
        ));
    }
    Ok(canonicalize(raw))
}

/// Canonicalize raw bytes into BYTES_PER_BLOB-length buffer.
/// Each 32-byte field element: [0x00, raw[0..31]].
fn canonicalize(raw: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; BYTES_PER_BLOB];
    let mut src_off = 0;
    let mut dst_off = 0;
    while src_off < raw.len() {
        dst_off += 1; // skip 0x00 high byte
        let take = BYTES_PER_FIELD_ELEMENT.min(raw.len() - src_off);
        out[dst_off..dst_off + take].copy_from_slice(&raw[src_off..src_off + take]);
        src_off += take;
        dst_off += BYTES_PER_FIELD_ELEMENT;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn encode_batch_payload_golden() {
        // Matches Go's tinyBlocks() test fixture from blob_test.go.
        let blocks = vec![
            FetchedBlock {
                header_rlp: vec![0xc1, 0x80],
                tx_envelopes: vec![vec![0x01, 0x02], vec![0x03, 0x04]],
            },
            FetchedBlock { header_rlp: vec![0xc2, 0x80, 0x80], tx_envelopes: vec![vec![0x05]] },
        ];
        let encoded = encode_batch_payload(&blocks);
        // Golden bytes from Go: d0 c9 c1 80 c6 82 01 02 82 03 04 c5 c2 80 80 c1 05
        let expected: Vec<u8> = vec![
            0xd0, 0xc9, 0xc1, 0x80, 0xc6, 0x82, 0x01, 0x02, 0x82, 0x03, 0x04, 0xc5, 0xc2, 0x80,
            0x80, 0xc1, 0x05,
        ];
        assert_eq!(encoded, expected, "must match Go golden bytes");
    }

    #[test]
    fn encode_compress_roundtrip() {
        let blocks = vec![FetchedBlock {
            header_rlp: vec![0xc1, 0x80],
            tx_envelopes: vec![vec![0x01, 0x02]],
        }];
        let payload = encode_batch_payload(&blocks);
        let compressed = brotli_compress(&payload).unwrap();

        let mut stream = Vec::with_capacity(1 + compressed.len());
        stream.push(BLOB_FORMAT_VERSION);
        stream.extend_from_slice(&compressed);

        // Verify version byte and brotli round-trip.
        assert_eq!(stream[0], 0x01);
        let mut decompressed = Vec::new();
        brotli::Decompressor::new(&stream[1..], 4096).read_to_end(&mut decompressed).unwrap();
        assert_eq!(decompressed, payload);
    }

    #[test]
    fn empty_blocks_encode() {
        let blocks = vec![FetchedBlock {
            header_rlp: vec![0xc0], // empty RLP list
            tx_envelopes: vec![],
        }];
        let encoded = encode_batch_payload(&blocks);
        // outer list [ block list [ 0xc0, empty txs list ] ]
        // block payload = 1 (headerRLP) + 1 (empty txs list 0xc0) = 2
        // outer payload = 1 (block header) + 2 = 3
        assert_eq!(encoded, vec![0xc3, 0xc2, 0xc0, 0xc0]);
    }
}
