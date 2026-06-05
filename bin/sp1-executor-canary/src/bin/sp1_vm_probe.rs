//! In-zkVM end-to-end probe: build a DPoS block's three guest inputs (witness,
//! blob, transcoded cert), run them through the real `rsp-client` SP1 ELF in the
//! SP1 **executor** (RISC-V emulation, no proof), and check the committed
//! `block_hash`. This validates BOTH tracks in the actual zkVM:
//!   - cert-verify (`verify_finalization`) executes in RISC-V — no panic ⇒ the committee read over
//!     witnessed state + the BLS pairing pass in-VM;
//!   - the committed `block_hash` (which commits `state_root`) matches the node ⇒ STF state-root
//!     parity holds in-VM.
//!
//! Run: `RPC_URL=http://localhost:8545 BLOCK=2560 SP1_ELF_PATH=./rsp-client-devnet.elf \
//!       CERT_HEX=0x.. sp1_vm_probe`  (CERT_HEX optional — omit to skip cert verify).

use std::sync::Arc;

use alloy_eips::Encodable2718;
use alloy_network::Ethereum;
use alloy_provider::{Provider, RootProvider};
use fluent_stf_primitives::fluent_chainspec;
use reth_chainspec::ChainSpec;
use rsp_blob_builder::{build_blobs_from_fetched, prepare_blob_verification_input, FetchedBlock};
use rsp_host_executor::EthHostExecutor;
use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};

const MAX_CERT_SIGNERS: usize = 4096;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let rpc_url = std::env::var("RPC_URL").unwrap_or_else(|_| "http://localhost:8545".into());
    let block: u64 = std::env::var("BLOCK").expect("BLOCK env var required").parse()?;
    let elf_path =
        std::env::var("SP1_ELF_PATH").unwrap_or_else(|_| "./rsp-client-devnet.elf".into());
    let provider: RootProvider<Ethereum> = rsp_provider::create_provider(rpc_url.parse()?)?;
    let chain_spec: Arc<ChainSpec> = Arc::new(fluent_chainspec());

    let node_block = provider
        .get_block_by_number(block.into())
        .await?
        .ok_or_else(|| eyre::eyre!("block {block} not found"))?;
    let node_hash = node_block.header.hash;

    // 1. Witness (host executor also asserts host-root == node-root).
    let host = EthHostExecutor::eth(chain_spec.clone(), None);
    let witness = host
        .execute(block, &provider, None, false)
        .await
        .map_err(|e| eyre::eyre!("witness build: {e:?}"))?;

    // 2. Blob input, built from the witnessed block (header RLP + 2718 tx envelopes).
    let header_rlp = alloy_rlp::encode(&witness.current_block.header);
    let tx_envelopes: Vec<Vec<u8>> =
        witness.current_block.body.transactions.iter().map(|tx| tx.encoded_2718()).collect();
    let raw_blobs = build_blobs_from_fetched(vec![FetchedBlock { header_rlp, tx_envelopes }])?;
    let blob_input = prepare_blob_verification_input(&raw_blobs)?;

    // 3. Cert input (optional): transcode the raw commonware cert hex from CERT_HEX.
    let cert_bytes = match std::env::var("CERT_HEX") {
        Ok(hex_str) if !hex_str.is_empty() => {
            let raw = hex::decode(hex_str.trim().strip_prefix("0x").unwrap_or(hex_str.trim()))?;
            let parts = dpos_cert_verify::transcode_finalization(&raw, MAX_CERT_SIGNERS)
                .map_err(|e| eyre::eyre!("cert transcode: {e}"))?;
            bincode::serialize(&nitro_types::CertVerifyInput {
                sig_g1: parts.sig_g1,
                bitmap: parts.bitmap,
                round_epoch: parts.round_epoch,
                round_view: parts.round_view,
                parent_view: parts.parent_view,
            })?
        }
        _ => Vec::new(),
    };
    eprintln!(
        "inputs ready: witness, blob ({} blobs), cert ({} bytes — {})",
        blob_input.blobs.len(),
        cert_bytes.len(),
        if cert_bytes.is_empty() { "verify SKIPPED" } else { "verify ENABLED" }
    );

    // 4. Run the guest ELF in the SP1 executor (RISC-V emulation, no proof).
    let elf_bytes = std::fs::read(&elf_path)?;
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&bincode::serialize(&witness)?);
    stdin.write_slice(&bincode::serialize(&blob_input)?);
    stdin.write_slice(&cert_bytes);

    sp1_sdk::utils::setup_logger();
    let client = ProverClient::builder().cpu().build().await;
    let (public_values, report) = client
        .execute(Elf::from(elf_bytes), stdin)
        .await
        .map_err(|e| eyre::eyre!("SP1 EXECUTE FAILED (guest panic — cert verify or STF): {e:?}"))?;
    eprintln!("guest executed: {} instructions", report.total_instruction_count());

    // 5. Committed layout: parent_hash(32) || block_hash(32) || ... — check block_hash.
    let pv = public_values.as_slice();
    eyre::ensure!(pv.len() >= 64, "public values too short: {} bytes", pv.len());
    let vm_block_hash = alloy_primitives::B256::from_slice(&pv[32..64]);
    eprintln!("vm   block_hash = {vm_block_hash}");
    eprintln!("node block_hash = {node_hash}");
    if vm_block_hash == node_hash {
        println!(
            "SP1_VM_OK block={block}: guest committed matching block_hash{}",
            if cert_bytes.is_empty() { "" } else { " AND cert verified in-VM" }
        );
        Ok(())
    } else {
        eyre::bail!("SP1_VM_MISMATCH block={block}: vm {vm_block_hash} != node {node_hash}")
    }
}
