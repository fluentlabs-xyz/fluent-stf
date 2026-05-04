//! MDBX-backed wrapper around `rsp_blob_builder`'s encoder. Reads
//! header + body from the orchestrator's driver factory, never hits
//! L2 RPC. Used by `sign_batch_io` and `handle_block_received`.

use std::sync::Arc;

use tracing::info;

use crate::driver::Driver;

/// Build canonical EIP-4844 blobs from MDBX-committed blocks. Returns
/// `Ok(None)` when `to_block` is above the driver's MDBX tip — the
/// caller's worker tick should retry. Otherwise byte-identical to
/// `rsp_blob_builder::build_blobs_from_l2(rpc, from, to)` for the same
/// (already-MDBX-committed) range.
pub(crate) async fn build_blobs_from_mdbx(
    driver: &Arc<Driver>,
    from_block: u64,
    to_block: u64,
) -> eyre::Result<Option<Vec<Vec<u8>>>> {
    let Some(blocks) = driver.collect_blob_inputs(from_block..=to_block).await? else {
        return Ok(None);
    };
    let blobs = rsp_blob_builder::build_blobs_from_fetched(blocks)?;
    info!(from_block, to_block, num_blobs = blobs.len(), "Built blobs from MDBX");
    Ok(Some(blobs))
}
