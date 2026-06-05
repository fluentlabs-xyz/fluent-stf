//! Shared blob decanonicalization and RLP-block streaming.
//!
//! Used by both SP1 (zkVM) and Nitro (enclave) runtimes.
//! SP1 call sites `.unwrap()`, Nitro propagates errors.

use std::io::Read;

use alloy_primitives::{keccak256, B256};
use alloy_rlp::Header;

pub(crate) const BYTES_PER_FIELD: usize = 31;
#[cfg(test)]
const FIELD_SIZE: usize = 32;
pub(crate) const FIELDS_PER_BLOB: usize = 4096;
pub(crate) const MAX_RAW_BYTES_PER_BLOB: usize = FIELDS_PER_BLOB * BYTES_PER_FIELD;

/// View of one RLP-encoded Ethereum block inside the decompressed blob payload.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BlockView {
    /// keccak256 over the raw RLP-encoded block header (bytes identical to
    /// `alloy_consensus::Header::hash_slow()`).
    pub(crate) block_hash: B256,
}

/// Extracts raw bytes from a single blob's KZG field elements.
pub(crate) fn decanonicalize(blob: &[u8]) -> Result<Vec<u8>, String> {
    if !blob.len().is_multiple_of(32) {
        return Err(format!("blob length ({}) is not a multiple of 32", blob.len()));
    }
    let mut result = Vec::with_capacity(MAX_RAW_BYTES_PER_BLOB);
    let mut offset = 0;
    while offset < blob.len() && result.len() < MAX_RAW_BYTES_PER_BLOB {
        if blob[offset] != 0x00 {
            return Err(format!("non-canonical field element at offset {offset}"));
        }
        offset += 1;
        let remaining = MAX_RAW_BYTES_PER_BLOB - result.len();
        let take = remaining.min(BYTES_PER_FIELD).min(blob.len() - offset);
        result.extend_from_slice(&blob[offset..offset + take]);
        offset += BYTES_PER_FIELD;
    }
    Ok(result)
}

/// Blob format version byte — cleartext prefix of the raw blob stream.
const BLOB_FORMAT_VERSION: u8 = 0x01;

/// Decanonicalize all blobs, strip version byte, and brotli-decompress.
pub(crate) fn decode_blob_payload(blobs: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    if blobs.is_empty() {
        return Err("no blobs provided".into());
    }
    let mut all_raw = Vec::with_capacity(blobs.len() * MAX_RAW_BYTES_PER_BLOB);
    for blob in blobs {
        let raw = decanonicalize(blob)?;
        all_raw.extend_from_slice(&raw);
    }
    if all_raw.is_empty() {
        return Err("empty raw stream after decanonicalization".into());
    }
    if all_raw[0] != BLOB_FORMAT_VERSION {
        return Err(format!(
            "unsupported blob format version: 0x{:02x}, expected 0x{:02x}",
            all_raw[0], BLOB_FORMAT_VERSION
        ));
    }
    let mut decompressed = Vec::new();
    brotli::Decompressor::new(&all_raw[1..], 4096)
        .read_to_end(&mut decompressed)
        .map_err(|e| format!("brotli decompression failed: {e}"))?;
    Ok(decompressed)
}

/// Streaming iterator over blocks in the Go-format RLP payload.
///
/// The payload is `rlp([ [headerRLP, [txEnv...]], ... ])`. This iterator
/// reads the outer list once, then yields one `BlockView` per inner block
/// list. `block_hash` = keccak256(headerRLP).
pub(crate) fn iter_blocks(payload: &[u8]) -> BlockIter<'_> {
    BlockIter { cursor: payload, initialized: false, remaining: 0, done: false }
}

pub(crate) struct BlockIter<'a> {
    cursor: &'a [u8],
    initialized: bool,
    remaining: usize,
    done: bool,
}

impl<'a> Iterator for BlockIter<'a> {
    type Item = Result<BlockView, String>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        // First call: decode the outer wrapping list.
        if !self.initialized {
            self.initialized = true;
            if self.cursor.is_empty() {
                return None;
            }
            let start = self.cursor;
            let mut peek = self.cursor;
            let outer = match Header::decode(&mut peek) {
                Ok(h) => h,
                Err(e) => {
                    self.done = true;
                    return Some(Err(format!("outer list RLP decode failed: {e}")));
                }
            };
            if !outer.list {
                self.done = true;
                return Some(Err("payload is not an RLP list".into()));
            }
            let header_len = start.len() - peek.len();
            let total = header_len + outer.payload_length;
            if total > start.len() {
                self.done = true;
                return Some(Err("outer list exceeds payload bounds".into()));
            }
            // Reject trailing bytes after the outer list.
            if total < start.len() {
                self.done = true;
                return Some(Err("trailing bytes after outer RLP list".into()));
            }
            self.cursor = peek;
            self.remaining = outer.payload_length;
        }

        if self.remaining == 0 {
            return None;
        }

        // Each block: [headerRLP, [txEnvelopes...]]
        let block_start = self.cursor;
        let mut peek = self.cursor;
        let block_hdr = match Header::decode(&mut peek) {
            Ok(h) => h,
            Err(e) => {
                self.done = true;
                return Some(Err(format!("block list RLP decode failed: {e}")));
            }
        };
        if !block_hdr.list {
            self.done = true;
            return Some(Err("block entry is not an RLP list".into()));
        }
        let block_header_len = block_start.len() - peek.len();
        let block_total = block_header_len + block_hdr.payload_length;
        if block_total > self.remaining {
            self.done = true;
            return Some(Err("block entry exceeds remaining payload".into()));
        }

        // First item in block list: headerRLP (an already-encoded RLP list).
        let inner = &block_start[block_header_len..block_header_len + block_hdr.payload_length];
        let mut inner_peek = inner;
        let header_meta = match Header::decode(&mut inner_peek) {
            Ok(h) => h,
            Err(e) => {
                self.done = true;
                return Some(Err(format!("header RLP decode failed: {e}")));
            }
        };
        if !header_meta.list {
            self.done = true;
            return Some(Err("header is not an RLP list".into()));
        }
        let header_prefix_len = inner.len() - inner_peek.len();
        let header_total = header_prefix_len + header_meta.payload_length;
        if header_total > inner.len() {
            self.done = true;
            return Some(Err("header RLP exceeds block bounds".into()));
        }
        let header_bytes = &inner[..header_total];
        let block_hash = keccak256(header_bytes);

        // Advance cursor past the entire block entry.
        self.cursor = &block_start[block_total..];
        self.remaining -= block_total;
        Some(Ok(BlockView { block_hash }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::Header as ConsensusHeader;

    /// Build a Go-compatible RLP payload from two empty blocks.
    /// Uses the same manual RLP construction as the blob-builder encoder.
    fn encode_two_blocks_go_format() -> (Vec<u8>, B256, B256) {
        let h1 = ConsensusHeader { number: 100, ..Default::default() };
        let h2 = ConsensusHeader { number: 101, ..Default::default() };

        let h1_rlp = alloy_rlp::encode(&h1);
        let h2_rlp = alloy_rlp::encode(&h2);

        // Each block: [headerRLP, []] (empty tx list)
        // block_payload = headerRLP.len() + 1 (empty list = 0xc0)
        let b1_payload = h1_rlp.len() + 1;
        let b2_payload = h2_rlp.len() + 1;

        let b1_total =
            alloy_rlp::Header { list: true, payload_length: b1_payload }.length() + b1_payload;
        let b2_total =
            alloy_rlp::Header { list: true, payload_length: b2_payload }.length() + b2_payload;
        let outer_payload = b1_total + b2_total;

        let mut payload = Vec::new();
        // Outer list
        alloy_rlp::Header { list: true, payload_length: outer_payload }.encode(&mut payload);
        // Block 1
        alloy_rlp::Header { list: true, payload_length: b1_payload }.encode(&mut payload);
        payload.extend_from_slice(&h1_rlp);
        alloy_rlp::Header { list: true, payload_length: 0 }.encode(&mut payload); // empty txs
                                                                                  // Block 2
        alloy_rlp::Header { list: true, payload_length: b2_payload }.encode(&mut payload);
        payload.extend_from_slice(&h2_rlp);
        alloy_rlp::Header { list: true, payload_length: 0 }.encode(&mut payload); // empty txs

        (payload, h1.hash_slow(), h2.hash_slow())
    }

    #[test]
    fn iter_blocks_yields_block_hashes_in_order() {
        let (payload, hash1, hash2) = encode_two_blocks_go_format();
        let mut it = iter_blocks(&payload);
        assert_eq!(it.next().unwrap().unwrap().block_hash, hash1);
        assert_eq!(it.next().unwrap().unwrap().block_hash, hash2);
        assert!(it.next().is_none());
    }

    #[test]
    fn iter_blocks_rejects_trailing_garbage() {
        let (mut payload, _, _) = encode_two_blocks_go_format();
        payload.push(0xFF);
        let mut it = iter_blocks(&payload);
        // First call should error on trailing bytes after outer list.
        assert!(it.next().unwrap().is_err());
    }

    #[test]
    fn iter_blocks_rejects_truncated_stream() {
        let (payload, _, _) = encode_two_blocks_go_format();
        let truncated = &payload[..payload.len() - 5];
        let mut it = iter_blocks(truncated);
        // The outer list header claims more bytes than available.
        assert!(it.next().unwrap().is_err());
    }

    #[test]
    fn iter_blocks_empty_payload() {
        let mut it = iter_blocks(&[]);
        assert!(it.next().is_none());
    }

    #[test]
    fn decode_blob_payload_version_check() {
        // Build a minimal blob: version 0x01 + brotli(some_data)
        let data = vec![0xc0]; // empty RLP list
        let mut compressed = Vec::new();
        {
            use std::io::Write;
            let mut enc = brotli::enc::writer::CompressorWriter::new(&mut compressed, 4096, 6, 22);
            enc.write_all(&data).unwrap();
        }
        // Canonicalize: version byte + compressed
        let mut stream = vec![BLOB_FORMAT_VERSION];
        stream.extend_from_slice(&compressed);
        // Pad to field-element-aligned blob
        let mut blob = vec![0u8; FIELDS_PER_BLOB * FIELD_SIZE];
        let mut src_off = 0;
        let mut dst_off = 0;
        while src_off < stream.len() {
            dst_off += 1;
            let take = BYTES_PER_FIELD.min(stream.len() - src_off);
            blob[dst_off..dst_off + take].copy_from_slice(&stream[src_off..src_off + take]);
            src_off += take;
            dst_off += BYTES_PER_FIELD;
        }
        let result = decode_blob_payload(&[blob]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), data);
    }

    #[test]
    fn decode_blob_payload_rejects_wrong_version() {
        let mut blob = vec![0u8; FIELDS_PER_BLOB * FIELD_SIZE];
        // Write version 0x02 at the first data byte position (offset 1 after 0x00 high byte)
        blob[1] = 0x02;
        let result = decode_blob_payload(&[blob]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unsupported blob format version"));
    }

    #[test]
    fn canonicalize_decanonicalize_roundtrip() {
        let raw: Vec<u8> = (0..MAX_RAW_BYTES_PER_BLOB).map(|i| (i % 251) as u8).collect();
        let mut blob = vec![0u8; FIELDS_PER_BLOB * FIELD_SIZE];
        let mut src_off = 0;
        let mut dst_off = 0;
        while src_off < raw.len() {
            dst_off += 1;
            let take = BYTES_PER_FIELD.min(raw.len() - src_off);
            blob[dst_off..dst_off + take].copy_from_slice(&raw[src_off..src_off + take]);
            src_off += take;
            dst_off += BYTES_PER_FIELD;
        }
        let decoded = decanonicalize(&blob).unwrap();
        assert_eq!(decoded, raw);
    }

    #[test]
    fn decanonicalize_rejects_non_canonical() {
        let mut blob = vec![0u8; FIELDS_PER_BLOB * FIELD_SIZE];
        blob[0] = 0x01;
        assert!(decanonicalize(&blob).is_err());
    }
}
