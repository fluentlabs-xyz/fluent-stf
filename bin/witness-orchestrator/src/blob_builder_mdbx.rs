use std::sync::Arc;

use tracing::info;

use crate::driver::Driver;

/// `Ok(None)` when `to_block` exceeds the driver's MDBX tip — caller's
/// next worker tick should retry. Output is byte-identical to
/// `rsp_blob_builder::build_blobs_from_l2(rpc, from, to)` for the same range.
pub async fn build_blobs_from_mdbx(
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
