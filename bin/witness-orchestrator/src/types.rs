// Used only by orchestrator-internal modules; lib target does not consume
// these but the `pub mod types` declaration in lib.rs forces compilation.
#[allow(unused_imports)]
pub(crate) use nitro_types::{
    EthExecutionResponse, InvalidSignaturesResponse, SignBatchRootRequest, SubmitBatchResponse,
};

/// Bincode-serialized `ClientExecutorInput<FluentPrimitives>` for `block_number`,
/// forwarded to the proving backend as-is.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProveRequest {
    pub block_number: u64,
    pub payload: Vec<u8>,
}
