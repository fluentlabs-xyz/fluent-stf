/// The port on which the enclave listens for incoming connections.
/// The parent host connects to this port to send execution tasks (STF) via VSOCK.
pub const VSOCK_PORT: u32 = 5005;

/// Maximum allowed size for a single data frame (512 MiB).
/// Acts as a security boundary to prevent memory exhaustion during stream reading.
/// Provisional — revisit once p99 legitimate frame size has been measured on real workloads.
pub const MAX_FRAME_SIZE: usize = 512 * 1024 * 1024;

/// Read timeout applied to every vsock stream accepted by the enclave.
/// On timeout, the connection is dropped and the accept loop continues.
pub const VSOCK_READ_TIMEOUT_SECS: u64 = 60;

/// Maximum number of concurrent `ExecuteBlock` jobs the enclave processes.
///
/// MUST match the enclave vCPU allocation — update `enclave_cli run` config in lock-step.
/// Provisional default, pending confirmation of the production vCPU count.
pub const EXECUTE_WORKER_COUNT: usize = 32;

/// The Reserved Context ID (CID) for the parent host.
/// In the Nitro Enclave architecture, the host is always reachable at CID 3.
pub const HOST_CID: u32 = 3;

/// The port on the parent host where the vsock-proxy is running.
/// This proxy forwards the enclave's encrypted traffic to the actual AWS KMS endpoint.
pub const KMS_PORT: u32 = 8000;

/// Per-read/per-write timeout applied to the KMS vsock stream.
pub const KMS_TIMEOUT_SECS: u64 = 30;

/// Upper bound on the KMS HTTP response body we are willing to buffer.
pub const KMS_MAX_RESPONSE_BYTES: u64 = 512 * 1024;

/// The AWS Region where the KMS service is located.
#[cfg(not(any(feature = "testnet", feature = "devnet")))]
pub const REGION: &str = "eu-central-2";

/// The AWS Region where the KMS service is located.
#[cfg(any(feature = "testnet", feature = "devnet"))]
pub const REGION: &str = "us-east-1";

/// The DNS hostname for the AWS KMS endpoint.
#[cfg(not(any(feature = "testnet", feature = "devnet")))]
pub const KMS_HOST: &str = "kms.eu-central-2.amazonaws.com";

/// The DNS hostname for the AWS KMS endpoint.
#[cfg(any(feature = "testnet", feature = "devnet"))]
pub const KMS_HOST: &str = "kms.us-east-1.amazonaws.com";

/// Required Content-Type header for AWS JSON RPC requests.
pub const CONTENT_TYPE: &str = "application/x-amz-json-1.1";

/// The X-Amz-Target header value for generating random bytes from KMS.
/// Used as a second independent entropy source alongside NSM GetRandom.
pub const TARGET_GENERATE_RANDOM: &str = "TrentService.GenerateRandom";
