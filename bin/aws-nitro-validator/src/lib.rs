#![no_std]

// Mutually-exclusive network feature guard.
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

extern crate alloc;

use alloc::vec::Vec;
use p384::ecdsa::{signature::DigestVerifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha384};
use sha3::Keccak256;

// ─── Wire format ─────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct CertData {
    #[serde(with = "serde_bytes")]
    pub tbs: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct GuestInput {
    /// SEC1-uncompressed (97 bytes) Nitro root CA pubkey. Anchored via SHA-384.
    pub root_pubkey: Vec<u8>,
    /// DER-encoded Subject DN of the Nitro root CA. Anchored via SHA-384.
    #[serde(with = "serde_bytes")]
    pub root_subject: Vec<u8>,
    /// [intermediate_0, …, leaf]. Each entry is raw TBS + outer DER signature.
    pub chain: Vec<CertData>,
    /// COSE_Sign1 protected header (bstr contents — NOT the bstr tag+length).
    #[serde(with = "serde_bytes")]
    pub cose_protected: Vec<u8>,
    /// COSE_Sign1 payload (the CBOR-encoded AttestationDoc).
    #[serde(with = "serde_bytes")]
    pub cose_payload: Vec<u8>,
    /// Raw 96-byte ECDSA P-384 COSE Sign1 signature (R || S).
    #[serde(with = "serde_bytes")]
    pub cose_signature: Vec<u8>,
}

// ─── Anchors ─────────────────────────────────────────────────────────────────
//
// Hardcoded SHA-384 anchors for the AWS Nitro root CA and the enclave PCR0.
// Rotating any of these constants means trusting a different root / image —
// treat them as security-critical. `EXPECTED_ROOT_PUBKEY_HASH` and
// `EXPECTED_ROOT_SUBJECT_HASH` are derived from the root CA DER shipped at
// `bin/proxy/src/attestation/root.der`. `EXPECTED_PCR0` is fixed per network
// feature.

pub const EXPECTED_ROOT_PUBKEY_HASH: [u8; 48] = [
    0x70, 0x86, 0x37, 0xb2, 0xaf, 0xd0, 0xda, 0x2a,
    0xfb, 0xcf, 0x8b, 0xf6, 0xe1, 0xe4, 0x28, 0x0c,
    0x28, 0xe7, 0xa0, 0xa9, 0xc2, 0x57, 0xdd, 0x8b,
    0xd4, 0x7a, 0x39, 0x48, 0xb4, 0x11, 0xeb, 0x2c,
    0x4d, 0x61, 0xf9, 0x0e, 0x79, 0xbe, 0x5f, 0x51,
    0x0a, 0xb1, 0xae, 0x24, 0x15, 0x14, 0xb6, 0x83,
];

pub const EXPECTED_ROOT_SUBJECT_HASH: [u8; 48] = [
    0xfe, 0x19, 0xf1, 0x6b, 0x73, 0xdc, 0xfd, 0xf7,
    0xad, 0xa6, 0x86, 0xb2, 0x6f, 0xbc, 0x26, 0x80,
    0x0e, 0x8b, 0x49, 0x33, 0xa0, 0xc1, 0xe7, 0xa9,
    0xb4, 0x0c, 0xd4, 0xea, 0x80, 0x9f, 0x18, 0x29,
    0xdc, 0x48, 0x8e, 0x14, 0x75, 0x3c, 0xbd, 0xe8,
    0x76, 0x86, 0xc4, 0xd9, 0x34, 0x39, 0xf0, 0x3e,
];

#[cfg(feature = "mainnet")]
pub const EXPECTED_PCR0: [u8; 48] = [
    0x70, 0x40, 0x5a, 0x47, 0x27, 0xbf, 0xc5, 0x54,
    0xc7, 0x32, 0x78, 0x81, 0x9a, 0x47, 0x3c, 0xa1,
    0xbe, 0x4f, 0x36, 0x68, 0xe2, 0x6b, 0x5d, 0x26,
    0x26, 0xb0, 0x1a, 0xa1, 0xd8, 0xda, 0x64, 0x72,
    0x20, 0x47, 0x9e, 0xe1, 0x6e, 0x78, 0x1b, 0x26,
    0x6d, 0xaf, 0x71, 0x56, 0x86, 0x80, 0x64, 0x62,
];

#[cfg(feature = "testnet")]
pub const EXPECTED_PCR0: [u8; 48] = [
    0x57, 0x0c, 0xce, 0x86, 0x11, 0x36, 0x5c, 0xc8,
    0x09, 0x31, 0xf6, 0x0a, 0x42, 0x70, 0xd3, 0xb5,
    0x9f, 0xee, 0xa2, 0x68, 0xde, 0x85, 0x1e, 0x0a,
    0xf3, 0x1f, 0xdf, 0xa6, 0x78, 0x40, 0x99, 0x4b,
    0x4b, 0x9c, 0x80, 0x08, 0xb4, 0xd0, 0xd4, 0x37,
    0x03, 0x21, 0x18, 0xc1, 0xda, 0x71, 0x80, 0x83,
];

#[cfg(feature = "devnet")]
pub const EXPECTED_PCR0: [u8; 48] = [
    0x05, 0xb4, 0xfb, 0xe6, 0x73, 0x07, 0x44, 0x17,
    0xab, 0xa2, 0xb8, 0x33, 0x65, 0x02, 0xc7, 0x89,
    0xaa, 0xfb, 0x7a, 0xeb, 0x74, 0x4b, 0xe4, 0x9b,
    0x88, 0xd3, 0xe6, 0x0c, 0x44, 0x51, 0xa3, 0x7c,
    0x2a, 0x48, 0x51, 0xab, 0x17, 0xca, 0xb6, 0xe9,
    0x6d, 0x80, 0xc3, 0xc5, 0x5b, 0x7f, 0xeb, 0x54,
];

/// DER-encoded AlgorithmIdentifier SEQUENCE body for ecdsa-with-SHA384
/// (OID 1.2.840.10045.4.3.3). Excludes the outer `30 0a` SEQUENCE header.
const ECDSA_WITH_SHA384_ALGID_BODY: [u8; 10] = [
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03,
];

// ─── CBOR walker ─────────────────────────────────────────────────────────────
//
// Minimal CBOR reader covering the shapes produced by AWS Nitro AttestationDoc
// serialization: uint / bstr / tstr / array / map / null. Supports both
// definite and indefinite length encodings (RFC 8949 §3).

struct Cbor<'a> {
    buf: &'a [u8],
    pos: usize,
}

/// `None` in the length position means indefinite-length encoding (info 31).
type Len = Option<u64>;

impl<'a> Cbor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read_u8(&mut self) -> u8 {
        assert!(self.pos < self.buf.len(), "cbor: eof");
        let b = self.buf[self.pos];
        self.pos += 1;
        b
    }

    fn read_bytes(&mut self, n: usize) -> &'a [u8] {
        let end = self.pos.checked_add(n).expect("cbor: overflow");
        assert!(end <= self.buf.len(), "cbor: eof");
        let s = &self.buf[self.pos..end];
        self.pos = end;
        s
    }

    fn peek_u8(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    /// Returns `(major_type, length)` where `length` is `None` for indefinite.
    fn read_head(&mut self) -> (u8, Len) {
        let ib = self.read_u8();
        let major = ib >> 5;
        let info = ib & 0x1f;
        let arg = match info {
            0..=23 => Some(info as u64),
            24 => Some(self.read_u8() as u64),
            25 => {
                let b = self.read_bytes(2);
                Some(u16::from_be_bytes([b[0], b[1]]) as u64)
            }
            26 => {
                let b = self.read_bytes(4);
                Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64)
            }
            27 => {
                let b = self.read_bytes(8);
                Some(u64::from_be_bytes([
                    b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                ]))
            }
            31 => {
                // Indefinite length (valid for majors 2/3/4/5) or break (major 7).
                None
            }
            _ => panic!("cbor: reserved info byte {}", info),
        };
        (major, arg)
    }

    /// Consume a break sentinel (`0xff`) if present; otherwise false.
    fn try_break(&mut self) -> bool {
        if self.peek_u8() == Some(0xff) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    /// Read a (possibly chunked) bstr/tstr and return its concatenated bytes.
    fn read_str_contents(&mut self, major_expected: u8, len: Len) -> Vec<u8> {
        match len {
            Some(n) => self.read_bytes(n as usize).to_vec(),
            None => {
                // Indefinite: concatenate definite chunks until break.
                let mut out: Vec<u8> = Vec::new();
                loop {
                    if self.try_break() {
                        break;
                    }
                    let (m, l) = self.read_head();
                    assert_eq!(m, major_expected, "cbor: indefinite chunk major mismatch");
                    let n = l.expect("cbor: nested indefinite not allowed");
                    out.extend_from_slice(self.read_bytes(n as usize));
                }
                out
            }
        }
    }

    /// Skip one CBOR data item recursively.
    fn skip_item(&mut self) {
        let (major, len) = self.read_head();
        match major {
            0 | 1 => {} // uint / nint
            2 | 3 => {
                let _ = self.read_str_contents(major, len);
            }
            4 => match len {
                Some(n) => {
                    for _ in 0..n {
                        self.skip_item();
                    }
                }
                None => {
                    while !self.try_break() {
                        self.skip_item();
                    }
                }
            },
            5 => match len {
                Some(n) => {
                    for _ in 0..n {
                        self.skip_item();
                        self.skip_item();
                    }
                }
                None => {
                    while !self.try_break() {
                        self.skip_item();
                        self.skip_item();
                    }
                }
            },
            7 => {
                // simple values (false/true/null/undefined) already fully
                // consumed by read_head; break (info 31) shouldn't appear here.
                assert!(len.is_some(), "cbor: unexpected break while skipping");
            }
            _ => panic!("cbor: unsupported major {}", major),
        }
    }

    fn expect_map(&mut self) -> Len {
        let (m, l) = self.read_head();
        assert_eq!(m, 5, "cbor: expected map");
        l
    }

    fn expect_tstr(&mut self) -> Vec<u8> {
        let (m, l) = self.read_head();
        assert_eq!(m, 3, "cbor: expected tstr");
        self.read_str_contents(3, l)
    }

    fn expect_uint(&mut self) -> u64 {
        let (m, l) = self.read_head();
        assert_eq!(m, 0, "cbor: expected uint");
        l.expect("cbor: uint cannot be indefinite")
    }

    /// Read an optional bstr field: either null (`0xf6`) or a bstr.
    fn expect_bstr_or_null(&mut self) -> Option<Vec<u8>> {
        if self.peek_u8() == Some(0xf6) {
            self.pos += 1;
            return None;
        }
        let (m, l) = self.read_head();
        assert_eq!(m, 2, "cbor: expected bstr");
        Some(self.read_str_contents(2, l))
    }
}

/// Iterate a map's (k, v) pairs regardless of definite/indefinite encoding,
/// invoking `f(cbor)` once per pair to consume the key and value.
fn iter_map<F: FnMut(&mut Cbor<'_>)>(c: &mut Cbor<'_>, len: Len, mut f: F) {
    match len {
        Some(n) => {
            for _ in 0..n {
                f(c);
            }
        }
        None => {
            while !c.try_break() {
                f(c);
            }
        }
    }
}

/// Walk a signed `AttestationDoc` payload and return `(pcr0, user_data, timestamp_ms)`.
/// `timestamp_ms` is the enclave-reported attestation time in milliseconds since
/// the Unix epoch (per AWS Nitro NSM spec).
fn parse_attestation_doc(payload: &[u8]) -> (Vec<u8>, Vec<u8>, u64) {
    let mut c = Cbor::new(payload);
    let top = c.expect_map();
    let mut pcr0: Option<Vec<u8>> = None;
    let mut user_data: Option<Vec<u8>> = None;
    let mut timestamp_ms: Option<u64> = None;

    iter_map(&mut c, top, |c| {
        let key = c.expect_tstr();
        match key.as_slice() {
            b"pcrs" => {
                let m = c.expect_map();
                iter_map(c, m, |c| {
                    let idx = c.expect_uint();
                    let val = c.expect_bstr_or_null().expect("pcr value must be bstr");
                    if idx == 0 {
                        assert!(pcr0.is_none(), "duplicate pcr0");
                        pcr0 = Some(val);
                    }
                });
            }
            b"user_data" => {
                let v = c.expect_bstr_or_null().expect("user_data must not be null");
                assert!(user_data.is_none(), "duplicate user_data");
                user_data = Some(v);
            }
            b"timestamp" => {
                let v = c.expect_uint();
                assert!(timestamp_ms.is_none(), "duplicate timestamp");
                timestamp_ms = Some(v);
            }
            _ => c.skip_item(),
        }
    });

    (
        pcr0.expect("attestation doc missing pcrs[0]"),
        user_data.expect("attestation doc missing user_data"),
        timestamp_ms.expect("attestation doc missing timestamp"),
    )
}

/// Encode a CBOR definite-length head for major type `major` with argument `arg`.
fn push_cbor_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let ib_hi = major << 5;
    if arg < 24 {
        out.push(ib_hi | arg as u8);
    } else if arg <= 0xff {
        out.push(ib_hi | 24);
        out.push(arg as u8);
    } else if arg <= 0xffff {
        out.push(ib_hi | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= 0xffff_ffff {
        out.push(ib_hi | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(ib_hi | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

/// Build COSE `Sig_structure = ["Signature1", protected, h'', payload]`.
fn build_sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + protected.len() + payload.len());
    out.push(0x84); // array(4)
    // tstr "Signature1"
    out.extend_from_slice(&[
        0x6a, b'S', b'i', b'g', b'n', b'a', b't', b'u', b'r', b'e', b'1',
    ]);
    push_cbor_head(&mut out, 2, protected.len() as u64);
    out.extend_from_slice(protected);
    out.push(0x40); // empty bstr (external_aad)
    push_cbor_head(&mut out, 2, payload.len() as u64);
    out.extend_from_slice(payload);
    out
}

// ─── DER walker (minimal, TBS-targeted) ──────────────────────────────────────

struct Der<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Der<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn eof(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn read_u8(&mut self) -> u8 {
        assert!(self.pos < self.buf.len(), "der: eof");
        let b = self.buf[self.pos];
        self.pos += 1;
        b
    }

    fn read_bytes(&mut self, n: usize) -> &'a [u8] {
        let end = self.pos.checked_add(n).expect("der: overflow");
        assert!(end <= self.buf.len(), "der: eof");
        let s = &self.buf[self.pos..end];
        self.pos = end;
        s
    }

    fn read_len(&mut self) -> usize {
        let b = self.read_u8();
        if b < 0x80 {
            b as usize
        } else {
            let n = (b & 0x7f) as usize;
            assert!(n > 0 && n <= 4, "der: absurd length encoding");
            let mut len = 0usize;
            for _ in 0..n {
                len = (len << 8) | self.read_u8() as usize;
            }
            len
        }
    }

    /// Read one TLV. Returns `(tag, content, raw_tlv)` where `raw_tlv` spans
    /// the tag+length+content bytes in the underlying buffer.
    fn read_tlv(&mut self) -> (u8, &'a [u8], &'a [u8]) {
        let start = self.pos;
        let tag = self.read_u8();
        let len = self.read_len();
        let content = self.read_bytes(len);
        let raw = &self.buf[start..self.pos];
        (tag, content, raw)
    }

    fn expect(&mut self, expected_tag: u8) -> &'a [u8] {
        let (tag, content, _) = self.read_tlv();
        assert_eq!(tag, expected_tag, "der: unexpected tag");
        content
    }
}

struct ParsedTbs<'a> {
    issuer: &'a [u8],
    subject: &'a [u8],
    spki: [u8; 97],
}

/// Parse a TBS certificate (the `tbsCertificate` field, WITH its outer
/// SEQUENCE header). Validates the signature algorithm OID and extracts
/// issuer DN, subject DN, and the 97-byte SEC1 SPKI.
fn parse_tbs(tbs: &[u8]) -> ParsedTbs<'_> {
    let mut outer = Der::new(tbs);
    let (tag, body, _) = outer.read_tlv();
    assert_eq!(tag, 0x30, "tbs: outer not SEQUENCE");
    assert!(outer.eof(), "tbs: trailing bytes after SEQUENCE");

    let mut d = Der::new(body);

    // [0] version — optional EXPLICIT tag 0
    if d.buf.get(d.pos).copied() == Some(0xa0) {
        let _ = d.read_tlv();
    }
    // serialNumber INTEGER
    let _ = d.expect(0x02);
    // signature AlgorithmIdentifier
    let sigalg = d.expect(0x30);
    assert_eq!(sigalg, ECDSA_WITH_SHA384_ALGID_BODY, "tbs: signature algorithm not ecdsa-with-SHA384");

    // issuer Name (SEQUENCE) — capture raw TLV
    let (itag, _, issuer_raw) = d.read_tlv();
    assert_eq!(itag, 0x30, "tbs: issuer not SEQUENCE");

    // validity SEQUENCE — skipped (time checks handled at contract layer per N-30)
    let (vtag, _, _) = d.read_tlv();
    assert_eq!(vtag, 0x30, "tbs: validity not SEQUENCE");

    // subject Name (SEQUENCE) — capture raw TLV
    let (stag, _, subject_raw) = d.read_tlv();
    assert_eq!(stag, 0x30, "tbs: subject not SEQUENCE");

    // subjectPublicKeyInfo SEQUENCE
    let spki_body = d.expect(0x30);
    let mut spki_d = Der::new(spki_body);
    // algorithm — ignored for intermediates, but we still validate the curve.
    let _ = spki_d.expect(0x30);
    // subjectPublicKey BIT STRING — content = unused-bits || raw bytes
    let bit_string = spki_d.expect(0x03);
    assert_eq!(bit_string.len(), 98, "tbs: spki BIT STRING not 98 bytes");
    assert_eq!(bit_string[0], 0x00, "tbs: spki unused-bits must be 0");
    assert_eq!(bit_string[1], 0x04, "tbs: spki not uncompressed P-384 point");
    let mut spki = [0u8; 97];
    spki.copy_from_slice(&bit_string[1..]);

    ParsedTbs {
        issuer: issuer_raw,
        subject: subject_raw,
        spki,
    }
}

// ─── P-384 helpers ───────────────────────────────────────────────────────────

fn verify_p384_der(issuer_key: &[u8; 97], data: &[u8], sig_bytes: &[u8]) {
    let vk = VerifyingKey::from_sec1_bytes(issuer_key).expect("invalid issuer pubkey");
    let digest = Sha384::new().chain_update(data);
    let sig = Signature::from_der(sig_bytes).expect("invalid DER signature");
    vk.verify_digest(digest, &sig)
        .expect("DER signature verification failed");
}

fn verify_p384_raw(issuer_key: &[u8; 97], data: &[u8], sig_bytes: &[u8]) {
    let vk = VerifyingKey::from_sec1_bytes(issuer_key).expect("invalid issuer pubkey");
    let digest = Sha384::new().chain_update(data);
    assert_eq!(sig_bytes.len(), 96, "raw P-384 signature must be 96 bytes");
    let sig = Signature::from_bytes(sig_bytes.into()).expect("invalid raw signature");
    vk.verify_digest(digest, &sig)
        .expect("raw signature verification failed");
}

// ─── Top-level verification ──────────────────────────────────────────────────

/// Returns `(abi_encoded_address, attestation_timestamp_seconds)`.
/// The timestamp is the enclave-reported attestation time converted from
/// milliseconds to seconds so it is directly comparable to `block.timestamp`.
pub fn verify(input: &GuestInput) -> ([u8; 32], u64) {
    // 1. Root anchors.
    assert_eq!(
        Sha384::digest(&input.root_pubkey)[..],
        EXPECTED_ROOT_PUBKEY_HASH,
        "root CA pubkey hash mismatch"
    );
    assert_eq!(
        Sha384::digest(&input.root_subject)[..],
        EXPECTED_ROOT_SUBJECT_HASH,
        "root CA subject hash mismatch"
    );
    assert_eq!(input.root_pubkey.len(), 97, "root pubkey must be 97 bytes");
    assert!(!input.chain.is_empty(), "empty cert chain");

    let mut issuer_key = [0u8; 97];
    issuer_key.copy_from_slice(&input.root_pubkey);

    // 2. Walk the chain, structurally parsing each TBS.
    //    Tricky lifetime: `prev_subject` borrows from `input.chain[i-1].tbs`,
    //    so we keep the index and re-parse when needed.
    for (i, cert) in input.chain.iter().enumerate() {
        let parsed = parse_tbs(&cert.tbs);

        let prev_subject: &[u8] = if i == 0 {
            &input.root_subject
        } else {
            parse_tbs(&input.chain[i - 1].tbs).subject
        };
        assert_eq!(parsed.issuer, prev_subject, "issuer/subject linkage");

        verify_p384_der(&issuer_key, &cert.tbs, &cert.signature);
        issuer_key = parsed.spki;
    }
    // `issuer_key` now holds the leaf public key, authenticated end-to-end.
    let leaf_key = issuer_key;

    // 3. Build Sig_structure and verify the COSE signature.
    let sig_structure = build_sig_structure(&input.cose_protected, &input.cose_payload);
    verify_p384_raw(&leaf_key, &sig_structure, &input.cose_signature);

    // 4. Structurally parse the signed payload to locate PCR0, user_data, and
    //    the enclave-reported attestation timestamp.
    let (pcr0, user_data, timestamp_ms) = parse_attestation_doc(&input.cose_payload);

    // 5. PCR0 equality.
    assert_eq!(pcr0.as_slice(), EXPECTED_PCR0, "PCR0 mismatch");

    // 6. user_data shape (65-byte uncompressed secp256k1 key).
    assert_eq!(user_data.len(), 65, "user_data must be 65 bytes");
    assert_eq!(user_data[0], 0x04, "user_data not uncompressed key");

    // 7. Convert NSM millisecond timestamp to seconds for on-chain comparison.
    assert!(timestamp_ms > 0, "attestation timestamp must be non-zero");
    let timestamp_sec = timestamp_ms / 1000;

    // 8. Ethereum address.
    let hash = Keccak256::digest(&user_data[1..]);
    let mut abi_encoded = [0u8; 32];
    abi_encoded[12..].copy_from_slice(&hash[12..]);
    (abi_encoded, timestamp_sec)
}
