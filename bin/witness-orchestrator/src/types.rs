pub(crate) use nitro_types::{
    EthExecutionResponse, InvalidSignaturesResponse, SignBatchRootRequest, SubmitBatchResponse,
};

/// Bincode-serialized `ClientExecutorInput<FluentPrimitives>` for `block_number`,
/// forwarded to the proving backend as-is.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct ProveRequest {
    pub(crate) block_number: u64,
    pub(crate) payload: Vec<u8>,
}
