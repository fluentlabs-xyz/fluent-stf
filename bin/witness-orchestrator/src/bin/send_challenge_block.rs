//! Operator-only one-shot CLI. Submits a `Rollup.challengeBlock(...)`
//! tx with the contract's challenge bond so a running
//! `witness-orchestrator` picks up the resulting `BlockChallenged` event
//! and resolves it. See `README.md` and `.env.example` for env-var
//! configuration.

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_network::TxSigner;
use alloy_primitives::{Address, Bytes, TxKind, B256, U256};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types::TransactionRequest;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use eyre::{eyre, Context, Result};
use fluent_stf_primitives::{
    BRIDGE_ADDRESS, BRIDGE_DEPOSIT_TOPIC, BRIDGE_ROLLBACK_TOPIC, BRIDGE_WITHDRAWAL_TOPIC,
    LEGACY_BRIDGE_WITHDRAWAL_TOPIC,
};
use l1_rollup_client::{challengeBlockCall, getBatchCall, L2BlockHeader, MerkleProof};
use rsp_host_executor::events_hash::{
    calculate_deposit_hash, calculate_withdrawal_root, count_deposits,
};
use tracing::info;

/// 0.01 ETH in wei — hardcoded `msg.value` for the challenge bond.
/// If the deployed `_challengeDepositAmount` differs, the contract
/// reverts with `IncorrectChallengeDeposit(expected, 0.01e18)`.
const BOND_WEI: u128 = 10_000_000_000_000_000;

/// Fixed EIP-1559 priority fee. The bin is one-shot, so a small
/// constant tip is sufficient — if the tx is underpriced the operator
/// just re-runs the tool.
const PRIORITY_FEE_WEI: u128 = 1_000_000_000;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let rpc_url = std::env::var("RPC_URL").wrap_err("RPC_URL is required")?;
    let l1_rpc_url = std::env::var("L1_RPC_URL").wrap_err("L1_RPC_URL is required")?;
    let l1_rollup_addr: Address = std::env::var("L1_ROLLUP_ADDR")
        .wrap_err("L1_ROLLUP_ADDR is required")?
        .parse()
        .wrap_err("Invalid L1_ROLLUP_ADDR")?;
    let challenger_key = std::env::var("L1_CHALLENGER_KEY").wrap_err(
        "L1_CHALLENGER_KEY is required (must hold CHALLENGER_ROLE; \
         distinct from L1_SUBMITTER_KEY)",
    )?;
    let batch_index: u64 = std::env::var("CHALLENGE_BATCH_INDEX")
        .wrap_err("CHALLENGE_BATCH_INDEX is required")?
        .parse()
        .wrap_err("CHALLENGE_BATCH_INDEX must parse as u64")?;
    let block_number: u64 = std::env::var("CHALLENGE_BLOCK_NUMBER")
        .wrap_err("CHALLENGE_BLOCK_NUMBER is required")?
        .parse()
        .wrap_err("CHALLENGE_BLOCK_NUMBER must parse as u64")?;

    let l1_url: url::Url = l1_rpc_url.parse().wrap_err("Invalid L1_RPC_URL")?;
    let l2_url: url::Url = rpc_url.parse().wrap_err("Invalid RPC_URL")?;
    let l1: RootProvider = rsp_provider::create_provider(l1_url)?;
    let l2: RootProvider = rsp_provider::create_provider(l2_url)?;

    let signer: PrivateKeySigner = challenger_key.parse().wrap_err("Invalid L1_CHALLENGER_KEY")?;
    let challenger_addr = signer.address();
    info!(%challenger_addr, batch_index, block_number, "send_challenge_block starting");

    let (from_block, to_block, batch_root) =
        resolve_batch_range(&l1, &l2, l1_rollup_addr, batch_index).await?;
    if !(from_block..=to_block).contains(&block_number) {
        return Err(eyre!(
            "CHALLENGE_BLOCK_NUMBER {block_number} not in batch {batch_index} \
             range [{from_block}..={to_block}]"
        ));
    }
    info!(from_block, to_block, %batch_root, "Resolved batch L2 range");

    let (headers, leaves) = build_headers_and_leaves(&l2, from_block, to_block).await?;
    let local_root = batch_merkle::calculate_merkle_root(&leaves);
    if local_root != batch_root {
        return Err(eyre!(
            "local merkle root {local_root} != on-chain batchRoot {batch_root} — \
             L2 RPC may be on a fork that diverges from the sequencer-submitted blob data"
        ));
    }

    let idx = (block_number - from_block) as usize;
    let (proof_nonce, proof_bytes) = batch_merkle::build_merkle_proof(&leaves, idx);
    let merkle_proof =
        MerkleProof { nonce: U256::from(proof_nonce), proof: Bytes::from(proof_bytes) };
    let commitment = leaves[idx];

    let calldata = Bytes::from(
        challengeBlockCall {
            batchIndex: U256::from(batch_index),
            blockHeader: headers[idx].clone(),
            blockProof: merkle_proof,
        }
        .abi_encode(),
    );
    let value = U256::from(BOND_WEI);

    // Pre-broadcast simulation. `from` must be set so the contract sees
    // the real signer address against the `onlyRole(CHALLENGER_ROLE)`
    // modifier; without it `_msgSender` is `address(0)` and the role
    // check reverts before any business-logic revert is reachable.
    l1.call(TransactionRequest {
        from: Some(challenger_addr),
        to: Some(l1_rollup_addr.into()),
        input: calldata.clone().into(),
        value: Some(value),
        ..Default::default()
    })
    .await
    .wrap_err("pre-broadcast eth_call simulation reverted (challengeBlock)")?;
    info!(%commitment, "simulation passed");

    let gas_estimate = l1
        .estimate_gas(TransactionRequest {
            from: Some(challenger_addr),
            to: Some(l1_rollup_addr.into()),
            input: calldata.clone().into(),
            value: Some(value),
            ..Default::default()
        })
        .await
        .wrap_err("estimate_gas failed")?;
    let gas_limit = (gas_estimate as f64 * 1.2) as u64;

    let gas_price = l1.get_gas_price().await.wrap_err("get_gas_price failed")?;
    let max_fee_per_gas = gas_price.saturating_mul(3) / 2;
    let max_priority_fee_per_gas = PRIORITY_FEE_WEI.min(max_fee_per_gas);

    let nonce = l1
        .get_transaction_count(challenger_addr)
        .pending()
        .await
        .wrap_err("get_transaction_count(pending) failed")?;
    let chain_id = l1.get_chain_id().await.wrap_err("get_chain_id failed")?;

    let mut tx = TxEip1559 {
        chain_id,
        nonce,
        gas_limit,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        to: TxKind::Call(l1_rollup_addr),
        value,
        access_list: Default::default(),
        input: calldata,
    };
    let sig = signer.sign_transaction(&mut tx).await.wrap_err("sign_transaction failed")?;
    let envelope = TxEnvelope::Eip1559(tx.into_signed(sig));
    let mut buf = Vec::new();
    envelope.encode_2718(&mut buf);
    let pending = l1.send_raw_transaction(&buf).await.wrap_err("send_raw_transaction failed")?;
    let tx_hash = *pending.tx_hash();

    info!(
        %tx_hash,
        nonce,
        gas_limit,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        bond_wei = BOND_WEI,
        batch_index,
        block_number,
        %commitment,
        "challengeBlock broadcast"
    );

    println!("{tx_hash:#x}");
    Ok(())
}

/// Resolve `(from_block, to_block, batchRoot)` from a single
/// `getBatch(batchIndex)` call plus one L2 `eth_getBlockByHash`.
/// Avoids walking `BatchCommitted` events page-by-page from the
/// rollup deploy block.
async fn resolve_batch_range(
    l1: &impl Provider,
    l2: &RootProvider,
    rollup: Address,
    batch_index: u64,
) -> Result<(u64, u64, B256)> {
    let raw = l1
        .call(TransactionRequest {
            to: Some(rollup.into()),
            input: Bytes::from(getBatchCall { batchIndex: U256::from(batch_index) }.abi_encode())
                .into(),
            ..Default::default()
        })
        .await
        .wrap_err_with(|| format!("eth_call getBatch({batch_index}) failed"))?;
    let record = getBatchCall::abi_decode_returns(&raw)
        .wrap_err_with(|| format!("decode getBatch({batch_index}) return"))?;
    let num_blocks: u64 = record.numberOfBlocks.try_into().wrap_err("numberOfBlocks overflow")?;
    let to_block_hash = record.toBlockHash;
    let to_block = l2
        .get_block_by_hash(to_block_hash)
        .await
        .wrap_err("get_block_by_hash(toBlockHash) failed")?
        .ok_or_else(|| eyre!("L2 block with hash {to_block_hash} not found on RPC_URL"))?
        .header
        .number;
    let from_block = to_block
        .checked_sub(num_blocks - 1)
        .ok_or_else(|| eyre!("from_block underflow: to={to_block} num_blocks={num_blocks}"))?;
    Ok((from_block, to_block, record.batchRoot))
}

/// Walk `[from..=to]` building one `L2BlockHeader` per block via
/// `eth_getBlockByNumber` + `eth_getBlockReceipts`, returning headers
/// in order alongside their leaf hashes.
async fn build_headers_and_leaves(
    l2: &RootProvider,
    from_block: u64,
    to_block: u64,
) -> Result<(Vec<L2BlockHeader>, Vec<B256>)> {
    let count = (to_block - from_block + 1) as usize;
    let mut headers: Vec<L2BlockHeader> = Vec::with_capacity(count);
    let mut leaves: Vec<B256> = Vec::with_capacity(count);
    for n in from_block..=to_block {
        let header = build_l2_block_header(l2, n).await?;
        leaves.push(batch_merkle::compute_leaf(
            header.previousBlockHash,
            header.blockHash,
            header.withdrawalRoot,
            header.depositRoot,
        ));
        headers.push(header);
    }
    Ok((headers, leaves))
}

/// Build one `L2BlockHeader` from L2 RPC.
async fn build_l2_block_header(l2: &RootProvider, block_number: u64) -> Result<L2BlockHeader> {
    let block = l2
        .get_block_by_number(block_number.into())
        .await
        .wrap_err_with(|| format!("get_block_by_number({block_number})"))?
        .ok_or_else(|| eyre!("L2 block {block_number} not found"))?;

    let receipts = l2
        .get_block_receipts(block_number.into())
        .await
        .wrap_err_with(|| format!("get_block_receipts({block_number})"))?
        .unwrap_or_default();

    let withdrawal_root = calculate_withdrawal_root(
        &receipts,
        BRIDGE_ADDRESS,
        BRIDGE_WITHDRAWAL_TOPIC,
        LEGACY_BRIDGE_WITHDRAWAL_TOPIC,
        BRIDGE_ROLLBACK_TOPIC,
    );
    let deposit_root = calculate_deposit_hash(&receipts, BRIDGE_ADDRESS, BRIDGE_DEPOSIT_TOPIC);
    let deposit_count = count_deposits(&receipts, BRIDGE_ADDRESS, BRIDGE_DEPOSIT_TOPIC);

    Ok(L2BlockHeader {
        previousBlockHash: block.header.parent_hash,
        blockHash: block.header.hash,
        withdrawalRoot: withdrawal_root,
        depositRoot: deposit_root,
        depositCount: deposit_count,
    })
}
