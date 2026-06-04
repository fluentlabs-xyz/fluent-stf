//! End-to-end committee-read over a real `EthClientExecutorInput` (task
//! `dpos_l1_rollup_committee_binding`, Phase 4/5 validation).
//!
//! Drives a live DPoS devnet node (the `local-dpos-smoke` stack) over RPC:
//!
//!   1. `HostExecutor::execute(block_n)` builds a real witness — WITH the Phase 4
//!      committee-coverage forced read, so the witness includes the staking committee +
//!      consensus-keys slots.
//!   2. The enclave-style read (`epoch_committee_snapshot` over the witnessed `TrieDB`) is replayed
//!      here: if Phase 4 coverage were absent, the witness would omit those slots and this read
//!      would panic fail-loud (`TrieDB.expect`). It succeeding proves the coverage works.
//!   3. The committee read from the witness is cross-checked against the node's own
//!      `getEpochCommittee` (a direct `eth_call`).
//!
//! Env-gated (needs the devnet up), so `#[ignore]` like the sibling RPC tests:
//!   TEST_RPC_URL=http://localhost:8545 \
//!   cargo test -p rsp-host-executor --no-default-features --features devnet \
//!     --test committee_read_rpc -- --ignored --nocapture

use std::{cell::RefCell, sync::Arc};

use alloy_primitives::{Address, Bytes};
use alloy_provider::{network::Ethereum, Provider, RootProvider};
use alloy_sol_types::{sol, SolCall};
use fluent_stf_primitives::{
    fluent_chainspec, DPOS_ACTIVATION_BLOCK, DPOS_STAKING_ADDRESS, EPOCH_BLOCK_INTERVAL,
};
use reth_chainspec::ChainSpec;
use reth_evm::{ConfigureEvm, Evm};
use revm::{
    context_interface::result::{ExecutionResult, Output},
    database::WrapDatabaseRef,
};
use rsp_client_executor::{
    evm::FluentEvmConfig,
    io::{EthClientExecutorInput, WitnessInput},
};
use rsp_host_executor::EthHostExecutor;
use url::Url;

sol! {
    function getEpochCommittee(uint64 epoch) external view returns (address[]);
}

/// Replays the enclave's witness-side committee read over `input`'s witness.
/// Panics (fail-loud) if a committee slot is missing from the witness — exactly
/// what Phase 4 coverage must prevent.
fn committee_from_witness(
    input: &EthClientExecutorInput,
    chain_spec: Arc<ChainSpec>,
    epoch: u64,
) -> Vec<Address> {
    let sealed_headers = input.sealed_headers().collect::<Vec<_>>();
    let trie_db = input.witness_db(&sealed_headers).expect("witness_db");
    let header = input.current_block.header.clone();
    let evm_config = FluentEvmConfig::new_with_default_factory(chain_spec);
    let evm = RefCell::new(evm_config.evm_for_block(WrapDatabaseRef(trie_db), &header).unwrap());

    let view = |to: Address, calldata: Bytes| -> Result<Bytes, dpos_cert_verify::Error> {
        let out = evm
            .borrow_mut()
            .transact_system_call(Address::ZERO, to, calldata)
            .map_err(|e| dpos_cert_verify::Error::Evm(format!("{e:?}")))?;
        match out.result {
            ExecutionResult::Success { output, .. } => match output {
                Output::Call(b) | Output::Create(b, _) => Ok(b),
            },
            ExecutionResult::Revert { output, .. } => {
                Err(dpos_cert_verify::Error::CallReverted(alloy_primitives::hex::encode(output)))
            }
            ExecutionResult::Halt { reason, .. } => {
                Err(dpos_cert_verify::Error::CallReverted(format!("halt: {reason:?}")))
            }
        }
    };

    let snap = dpos_cert_verify::epoch_committee_snapshot(
        &view,
        input.current_block.header.number,
        epoch,
        DPOS_STAKING_ADDRESS,
    )
    .expect("committee read over witness");

    // Building the commonware scheme proves every member's consensus keys
    // decoded (a keyless member would have errored above).
    dpos_cert_verify::epoch_committee_from_snapshot(&snap).expect("committee bimap");

    snap.validators.iter().map(|v| v.address).collect()
}

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn committee_read_over_real_witness_matches_node() {
    let rpc_url: Url = std::env::var("TEST_RPC_URL")
        .unwrap_or_else(|_| "http://localhost:8545".to_string())
        .parse()
        .expect("invalid TEST_RPC_URL");
    let provider = RootProvider::<Ethereum>::new_http(rpc_url);

    // Pick a finalized block safely inside a committed epoch (>= activation +
    // one interval), or honour TEST_BLOCK_NUMBER.
    let block_number: u64 = match std::env::var("TEST_BLOCK_NUMBER") {
        Ok(v) => v.parse().expect("invalid TEST_BLOCK_NUMBER"),
        Err(_) => {
            let finalized = provider
                .get_block_by_number(alloy_rpc_types::BlockNumberOrTag::Finalized)
                .await
                .expect("get finalized")
                .expect("finalized block exists")
                .header
                .number;
            assert!(
                finalized >= DPOS_ACTIVATION_BLOCK + EPOCH_BLOCK_INTERVAL as u64,
                "finalized {finalized} has not reached a committed DPoS epoch \
                 (activation {DPOS_ACTIVATION_BLOCK} + interval {EPOCH_BLOCK_INTERVAL}); \
                 let the smoke run further"
            );
            finalized - 1
        }
    };

    let epoch =
        dpos_cert_verify::epoch_of_block(block_number, EPOCH_BLOCK_INTERVAL, DPOS_ACTIVATION_BLOCK);
    eprintln!("block_number={block_number} epoch={epoch}");

    let chain_spec: Arc<ChainSpec> = Arc::new(fluent_chainspec());
    let host = EthHostExecutor::eth(chain_spec.clone(), None);

    // (1)+(2): build the witness (with Phase 4 coverage) and read the committee
    // back out of it.
    let input = host.execute(block_number, &provider, None, false).await.expect("host execute");
    let from_witness = committee_from_witness(&input, chain_spec, epoch);
    assert!(!from_witness.is_empty(), "committee read from witness is empty for epoch {epoch}");

    // (3): cross-check against the node's own view.
    let cd = getEpochCommitteeCall { epoch }.abi_encode();
    let tx =
        alloy_rpc_types::TransactionRequest::default().to(DPOS_STAKING_ADDRESS).input(cd.into());
    let ret = provider.call(tx).await.expect("eth_call getEpochCommittee");
    let from_node = getEpochCommitteeCall::abi_decode_returns(&ret).expect("decode committee");

    assert_eq!(
        from_witness, from_node,
        "committee read from the EthClientExecutorInput witness must match the node's \
         getEpochCommittee (contract order)"
    );
    eprintln!("OK: {} validators, witness == node", from_witness.len());
}
