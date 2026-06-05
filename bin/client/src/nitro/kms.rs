use hmac::{Hmac, Mac};
use nitro_types::AwsCredentials;
use rustls::{ClientConfig, ClientConnection, OwnedTrustAnchor, RootCertStore, StreamOwned};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    sync::Arc,
    time::Duration,
};
use vsock::{VsockAddr, VsockStream};

use base64::{engine::general_purpose, Engine as _};

use crate::nitro::{
    CONTENT_TYPE, HOST_CID, KMS_HOST, KMS_MAX_RESPONSE_BYTES, KMS_PORT, KMS_TIMEOUT_SECS, REGION,
    TARGET_GENERATE_RANDOM,
};

/// Reject header values that could enable CRLF injection or NUL-termination
/// attacks when concatenated into the raw HTTP request.
fn assert_header_safe(name: &str, value: &str) -> anyhow::Result<()> {
    if value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return Err(anyhow::anyhow!("unsafe bytes in header value: {name}"));
    }
    Ok(())
}

/// Minimal KMS client used solely to obtain random bytes via `GenerateRandom`.
/// Serves as a second independent entropy source alongside NSM GetRandom.
pub struct KmsClient {
    creds: AwsCredentials,
    region: String,
    host: String,
    vsock_addr: VsockAddr,
}

impl KmsClient {
    pub fn new(creds: AwsCredentials) -> Self {
        Self {
            creds,
            region: REGION.to_string(),
            host: KMS_HOST.to_string(),
            vsock_addr: VsockAddr::new(HOST_CID, KMS_PORT),
        }
    }

    /// Requests 32 random bytes from KMS as an independent entropy source.
    pub fn generate_random(&self) -> anyhow::Result<Vec<u8>> {
        let body = serde_json::json!({
            "NumberOfBytes": 32
        });

        let resp = self.call_kms(TARGET_GENERATE_RANDOM, body)?;

        let b64_str = resp
            .get("Plaintext")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Response missing Plaintext field"))?;

        general_purpose::STANDARD
            .decode(b64_str)
            .map_err(|e| anyhow::anyhow!("Failed to decode Plaintext: {e}"))
    }

    // -----------------------------------------------------------------------
    // HTTP / SigV4 / VSOCK internals
    // -----------------------------------------------------------------------

    fn call_kms(&self, target: &str, body: serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let body_str = body.to_string();
        let http_req = self.build_signed_request(target, &body_str)?;

        let mut tls = self.connect()?;
        tls.write_all(http_req.as_bytes())?;
        tls.flush()?;

        // Per-read/per-write timeouts on the underlying vsock stream bound the
        // duration of any single I/O op. We read `KMS_MAX_RESPONSE_BYTES + 1`
        // so we can distinguish "response exactly fits the cap" from "response
        // hit the cap and was truncated".
        let mut resp_str = String::new();
        let cap = KMS_MAX_RESPONSE_BYTES;
        let n = (&mut tls)
            .take(cap + 1)
            .read_to_string(&mut resp_str)
            .map_err(|e| anyhow::anyhow!("Failed to read KMS response: {e}"))?;
        if n as u64 > cap {
            return Err(anyhow::anyhow!("KMS response exceeded {cap}-byte cap"));
        }

        let (status_line, body_part) = self.split_http(&resp_str);

        let status_code = self.parse_status_code(status_line)?;
        if !(200..300).contains(&status_code) {
            return Err(anyhow::anyhow!("KMS returned HTTP {}: {}", status_code, body_part));
        }

        let parsed: serde_json::Value = serde_json::from_str(body_part)?;

        if let Some(err) = parsed.get("__type") {
            return Err(anyhow::anyhow!("KMS API Error {}: {}", err, body_part));
        }

        Ok(parsed)
    }

    fn connect(&self) -> anyhow::Result<StreamOwned<ClientConnection, VsockStream>> {
        let vsock = VsockStream::connect(&self.vsock_addr)?;
        let timeout = Duration::from_secs(KMS_TIMEOUT_SECS);
        vsock
            .set_read_timeout(Some(timeout))
            .map_err(|e| anyhow::anyhow!("Failed to set KMS vsock read timeout: {e}"))?;
        vsock
            .set_write_timeout(Some(timeout))
            .map_err(|e| anyhow::anyhow!("Failed to set KMS vsock write timeout: {e}"))?;

        let mut roots = RootCertStore::empty();
        roots.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject.as_ref(),
                ta.subject_public_key_info.as_ref(),
                ta.name_constraints.as_ref().map(|nc| nc.as_ref()),
            )
        }));

        let config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let server_name = self.host.as_str().try_into()?;
        let conn = ClientConnection::new(Arc::new(config), server_name)?;

        Ok(StreamOwned::new(conn, vsock))
    }

    fn build_signed_request(&self, target: &str, body: &str) -> anyhow::Result<String> {
        let now = chrono::Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();

        assert_header_safe("host", self.host.as_str())?;
        assert_header_safe("x-amz-date", amz_date.as_str())?;
        assert_header_safe("x-amz-security-token", &self.creds.session_token)?;
        assert_header_safe("access_key_id", &self.creds.access_key_id)?;
        assert_header_safe("secret_access_key", &self.creds.secret_access_key)?;

        let mut headers = vec![
            ("content-type", CONTENT_TYPE),
            ("host", self.host.as_str()),
            ("x-amz-date", amz_date.as_str()),
            ("x-amz-target", target),
        ];

        headers.push(("x-amz-security-token", &self.creds.session_token));

        headers.sort_by_key(|a| a.0);

        let canonical_headers: String =
            headers.iter().map(|(k, v)| format!("{}:{}\n", k, v.trim())).collect();
        let signed_headers =
            headers.iter().map(|(k, _)| k.to_string()).collect::<Vec<_>>().join(";");

        let payload_hash = hex::encode(Sha256::digest(body.as_bytes()));
        let canonical_request =
            format!("POST\n/\n\n{}\n{}\n{}", canonical_headers, signed_headers, payload_hash);

        let credential_scope = format!("{}/{}/kms/aws4_request", date_stamp, self.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            amz_date,
            credential_scope,
            hex::encode(Sha256::digest(canonical_request.as_bytes()))
        );
        let signing_key = self.get_signature_key(&date_stamp);
        let signature = hex::encode(self.hmac_sha256(&signing_key, string_to_sign.as_bytes()));

        let mut req = String::from("POST / HTTP/1.1\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
        for (k, v) in &headers {
            req.push_str(&format!("{}: {}\r\n", k, v));
        }
        let auth_header = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.creds.access_key_id, credential_scope, signed_headers, signature
        );
        req.push_str(&format!("Authorization: {}\r\n", auth_header));
        req.push_str("Connection: close\r\n");
        req.push_str("\r\n");
        req.push_str(body);

        Ok(req)
    }

    fn get_signature_key(&self, date: &str) -> Vec<u8> {
        let k_date = self.hmac_sha256(
            format!("AWS4{}", self.creds.secret_access_key).as_bytes(),
            date.as_bytes(),
        );
        let k_region = self.hmac_sha256(&k_date, self.region.as_bytes());
        let k_service = self.hmac_sha256(&k_region, b"kms");
        self.hmac_sha256(&k_service, b"aws4_request")
    }

    fn hmac_sha256(&self, key: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key length");
        mac.update(msg);
        mac.finalize().into_bytes().to_vec()
    }

    fn split_http<'a>(&self, resp: &'a str) -> (&'a str, &'a str) {
        resp.find("\r\n\r\n").map(|i| (&resp[..i], &resp[i + 4..])).unwrap_or((resp, ""))
    }

    fn parse_status_code(&self, headers: &str) -> anyhow::Result<u16> {
        headers
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .ok_or_else(|| anyhow::anyhow!("Failed to parse HTTP status code"))
    }
}
