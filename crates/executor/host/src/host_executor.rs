use std::sync::Arc;

use crate::HostError;
use alloy_consensus::{BlockHeader, Header, TxReceipt};
use alloy_network::BlockResponse;
use alloy_primitives::{Bloom, Sealable, B256};
use alloy_provider::{Network, Provider};
use reth_chainspec::ChainSpec;
use reth_evm::{
    execute::{BasicBlockExecutor, Executor},
    ConfigureEvm,
};
use reth_primitives_traits::{Block, SealedHeader};
use reth_trie::{HashedPostState, KeccakKeyHasher};
use revm::database::CacheDB;
use revm_primitives::Address;
use rsp_client_executor::{
    evm::FluentEvmConfig, io::ClientExecutorInput, BlockValidator, IntoInput, IntoPrimitives,
};
use rsp_rpc_db::RpcDb;

pub type EthHostExecutor = HostExecutor<FluentEvmConfig, ChainSpec>;

/// An executor that fetches data from a [Provider] to execute blocks in the [ClientExecutor].
#[derive(Debug, Clone)]
pub struct HostExecutor<C: ConfigureEvm, CS> {
    evm_config: C,
    chain_spec: Arc<CS>,
}

impl EthHostExecutor {
    pub fn eth(chain_spec: Arc<ChainSpec>, _custom_beneficiary: Option<Address>) -> Self {
        Self {
            evm_config: FluentEvmConfig::new_with_default_factory(chain_spec.clone()),
            chain_spec,
        }
    }
}

impl<C: ConfigureEvm, CS> HostExecutor<C, CS> {
    /// Creates a new [HostExecutor].
    pub fn new(evm_config: C, chain_spec: Arc<CS>) -> Self {
        Self { evm_config, chain_spec }
    }

    /// Executes the block with the given block number using an RPC provider.
    pub async fn execute<P, N>(
        &self,
        block_number: u64,
        provider: &P,
        custom_beneficiary: Option<Address>,
        opcode_tracking: bool,
    ) -> Result<ClientExecutorInput<C::Primitives>, HostError>
    where
        C::Primitives: IntoPrimitives<N> + IntoInput + BlockValidator<CS>,
        P: Provider<N> + Clone + std::fmt::Debug,
        N: Network,
    {
        // Fetch the current block and the previous block from the provider.
        tracing::info!("fetching the current block and the previous block");
        let rpc_block = provider
            .get_block_by_number(block_number.into())
            .full()
            .await?
            .ok_or(HostError::ExpectedBlock(block_number))?;

        let current_block = C::Primitives::into_primitive_block(rpc_block.clone());

        let previous_block = provider
            .get_block_by_number((block_number - 1).into())
            .full()
            .await?
            .ok_or(HostError::ExpectedBlock(block_number))
            .map(C::Primitives::into_primitive_block)?;

        // Setup the database for the block executor.
        tracing::info!("setting up the database for the block executor");
        #[cfg(not(feature = "execution-witness"))]
        let rpc_db = rsp_rpc_db::BasicRpcDb::new(
            provider.clone(),
            block_number - 1,
            previous_block.header().state_root(),
        );
        #[cfg(feature = "execution-witness")]
        let rpc_db = rsp_rpc_db::ExecutionWitnessRpcDb::new(
            provider.clone(),
            block_number - 1,
            previous_block.header().state_root(),
        )
        .await?;

        let cache_db = CacheDB::new(&rpc_db);

        let block_executor = BasicBlockExecutor::new(self.evm_config.clone(), cache_db.clone());

        let block = current_block
            .clone()
            .try_into_recovered()
            .map_err(|_| HostError::FailedToRecoverSenders)?;

        // Validate the block header.
        C::Primitives::validate_header(
            &SealedHeader::seal_slow(C::Primitives::into_consensus_header(
                rpc_block.header().clone(),
            )),
            self.chain_spec.clone(),
        )?;

        let execution_output = block_executor.execute(&block)?;

        let output_addresses: Vec<_> = execution_output.state.state.keys().collect();
        tracing::info!("Addresses in execution_output: {:?}", output_addresses);

        // Validate the block post execution.
        tracing::info!("validating the block post execution");
        C::Primitives::validate_block_post_execution(
            &block,
            self.chain_spec.clone(),
            &execution_output,
        )?;

        // Accumulate the logs bloom.
        let mut logs_bloom = Bloom::default();
        execution_output.result.receipts.iter().for_each(|r| {
            logs_bloom.accrue_bloom(&r.bloom());
        });

        let state = rpc_db.state(&execution_output.state).await?;

        // Verify the state root.
        tracing::info!("verifying the state root");
        let state_root = {
            let mut mutated_state = state.clone();
            mutated_state.update(&HashedPostState::from_bundle_state::<KeccakKeyHasher>(
                &execution_output.state.state,
            ));
            mutated_state.state_root()
        };

        if state_root != current_block.header().state_root() {
            return Err(HostError::StateRootMismatch(
                state_root,
                current_block.header().state_root(),
            ));
        }

        // Derive and verify the block header.
        let header = derive_header(current_block.header(), state_root, logs_bloom);
        let ancestor_headers = rpc_db.ancestor_headers().await?;
        verify_header_hash(&header, current_block.header())?;

        tracing::info!(
            "successfully executed block: block_number={}, block_hash={}, state_root={}",
            current_block.header().number(),
            header.hash_slow(),
            state_root
        );

        // Create the client input.
        let client_input = ClientExecutorInput {
            current_block: C::Primitives::into_input_block(current_block),
            ancestor_headers,
            parent_state: state,
            bytecodes: rpc_db.bytecodes(),
            custom_beneficiary,
            opcode_tracking,
        };
        tracing::info!("successfully generated client input");

        Ok(client_input)
    }

    /// Executes the block using a reth provider factory from an ExEx context.
    pub fn execute_exex<P>(
        &self,
        block_number: u64,
        provider: P,
        custom_beneficiary: Option<Address>,
    ) -> Result<ClientExecutorInput<C::Primitives>, HostError>
    where
        C::Primitives: IntoInput
            + BlockValidator<CS>
            + reth_primitives_traits::NodePrimitives<BlockHeader = Header>,
        P: reth_provider::StateProviderFactory
            + reth_provider::HeaderProvider<Header = Header>
            + reth_provider::BlockReader<
                Block = <C::Primitives as reth_primitives_traits::NodePrimitives>::Block,
            > + Clone
            + std::fmt::Debug,
    {
        // Fetch blocks directly from reth storage — no RPC, no conversion.
        tracing::info!(block_number, "fetching current and previous block");
        let current_block = provider
            .block_by_number(block_number)
            .map_err(|_| HostError::ExpectedBlock(block_number))?
            .ok_or(HostError::ExpectedBlock(block_number))?;

        let previous_block = provider
            .block_by_number(block_number - 1)
            .map_err(|_| HostError::ExpectedBlock(block_number - 1))?
            .ok_or(HostError::ExpectedBlock(block_number - 1))?;

        // Set up ExExDb with cached before-provider.
        tracing::info!(block_number, "setting up ExExDb");
        let exex_db = rsp_rpc_db::ExExDb::new(
            provider,
            block_number,
            current_block.header().parent_hash(),
            previous_block.header().state_root(),
        )?;

        let cache_db = CacheDB::new(&exex_db);
        let block_executor = BasicBlockExecutor::new(self.evm_config.clone(), cache_db);

        let block = current_block
            .clone()
            .try_into_recovered()
            .map_err(|_| HostError::FailedToRecoverSenders)?;

        // Validate the block header.
        C::Primitives::validate_header(
            &SealedHeader::seal_slow(current_block.header().clone()),
            self.chain_spec.clone(),
        )?;

        let execution_output = block_executor.execute(&block)?;

        // Validate the block post execution.
        tracing::info!(block_number, "validating block post execution");
        C::Primitives::validate_block_post_execution(
            &block,
            self.chain_spec.clone(),
            &execution_output,
        )?;

        // Accumulate logs bloom.
        let mut logs_bloom = Bloom::default();
        execution_output.result.receipts.iter().for_each(|r| {
            logs_bloom.accrue_bloom(&r.bloom());
        });

        // Build the sparse trie witness.
        let state = exex_db.state(&execution_output.state)?;

        // Verify the state root WITHOUT cloning the entire trie.
        tracing::info!(block_number, "verifying state root");
        let hashed_post_state =
            HashedPostState::from_bundle_state::<KeccakKeyHasher>(&execution_output.state.state);
        let state_root = {
            let mut verification_state = state.clone();
            verification_state.update(&hashed_post_state);
            verification_state.state_root()
        };

        if state_root != current_block.header().state_root() {
            return Err(HostError::StateRootMismatch(
                state_root,
                current_block.header().state_root(),
            ));
        }

        // Derive and verify the header.
        let header = derive_header(current_block.header(), state_root, logs_bloom);
        let ancestor_headers = exex_db.ancestor_headers()?;
        verify_header_hash(&header, current_block.header())?;

        tracing::info!(
            block_number,
            block_hash = %header.hash_slow(),
            %state_root,
            "successfully executed block"
        );

        // Build the client input.
        let client_input = ClientExecutorInput {
            current_block: C::Primitives::into_input_block(current_block),
            ancestor_headers,
            parent_state: state,
            bytecodes: exex_db.bytecodes(),
            custom_beneficiary,
            opcode_tracking: false, // Use cfg feature for guest, not runtime bool
        };

        Ok(client_input)
    }

    /// Executes the block using pre-fetched block data from an ExEx notification.
    ///
    /// Unlike [`execute_exex`], this method does **not** call
    /// `provider.block_by_number()` for the current or previous block.
    /// Instead, the caller supplies:
    /// - `current_block` — the block to execute (from `chain.blocks_iter()`)
    /// - `parent_state_root` — the `state_root` of block N-1
    ///
    /// The provider is still required for:
    /// - `ExExDb` (historical state, multiproofs, ancestor headers, block hashes)
    ///
    /// This eliminates the "RPC didn't have expected block height" error that
    /// occurs during sync/catchup when the provider hasn't indexed the block yet
    /// but the ExEx notification already contains it.
    pub fn execute_exex_with_block<P>(
        &self,
        current_block: <C::Primitives as reth_primitives_traits::NodePrimitives>::Block,
        parent_state_root: B256,
        provider: P,
        custom_beneficiary: Option<Address>,
    ) -> Result<ClientExecutorInput<C::Primitives>, HostError>
    where
        C::Primitives: IntoInput
            + BlockValidator<CS>
            + reth_primitives_traits::NodePrimitives<BlockHeader = Header>,
        P: reth_provider::StateProviderFactory
            + reth_provider::HeaderProvider<Header = Header>
            + reth_provider::BlockReader<
                Block = <C::Primitives as reth_primitives_traits::NodePrimitives>::Block,
            > + Clone
            + std::fmt::Debug,
    {
        let block_number = current_block.header().number();
        tracing::info!(block_number, "executing block with pre-fetched block data");

        // Set up ExExDb — uses parent_state_root directly instead of reading
        // the previous block from provider.
        let exex_db = rsp_rpc_db::ExExDb::new(
            provider,
            block_number,
            current_block.header().parent_hash(),
            parent_state_root,
        )?;

        let cache_db = CacheDB::new(&exex_db);
        let block_executor = BasicBlockExecutor::new(self.evm_config.clone(), cache_db);

        let block = current_block
            .clone()
            .try_into_recovered()
            .map_err(|_| HostError::FailedToRecoverSenders)?;

        // Validate the block header.
        C::Primitives::validate_header(
            &SealedHeader::seal_slow(current_block.header().clone()),
            self.chain_spec.clone(),
        )?;

        let execution_output = block_executor.execute(&block)?;

        // Validate the block post execution.
        tracing::info!(block_number, "validating block post execution");
        C::Primitives::validate_block_post_execution(
            &block,
            self.chain_spec.clone(),
            &execution_output,
        )?;

        // Accumulate logs bloom.
        let mut logs_bloom = Bloom::default();
        execution_output.result.receipts.iter().for_each(|r| {
            logs_bloom.accrue_bloom(&r.bloom());
        });

        // Build the sparse trie witness.
        let state = exex_db.state(&execution_output.state)?;

        // Verify the state root.
        tracing::info!(block_number, "verifying state root");
        let hashed_post_state =
            HashedPostState::from_bundle_state::<KeccakKeyHasher>(&execution_output.state.state);
        let state_root = {
            let mut verification_state = state.clone();
            verification_state.update(&hashed_post_state);
            verification_state.state_root()
        };

        if state_root != current_block.header().state_root() {
            return Err(HostError::StateRootMismatch(
                state_root,
                current_block.header().state_root(),
            ));
        }

        // Derive and verify the header.
        let header = derive_header(current_block.header(), state_root, logs_bloom);
        let ancestor_headers = exex_db.ancestor_headers()?;
        verify_header_hash(&header, current_block.header())?;

        tracing::info!(
            block_number,
            block_hash = %header.hash_slow(),
            %state_root,
            "successfully executed block"
        );

        // Build the client input.
        let client_input = ClientExecutorInput {
            current_block: C::Primitives::into_input_block(current_block),
            ancestor_headers,
            parent_state: state,
            bytecodes: exex_db.bytecodes(),
            custom_beneficiary,
            opcode_tracking: false,
        };

        Ok(client_input)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn derive_header(block_header: &impl BlockHeader, state_root: B256, logs_bloom: Bloom) -> Header {
    Header {
        parent_hash: block_header.parent_hash(),
        ommers_hash: block_header.ommers_hash(),
        beneficiary: block_header.beneficiary(),
        state_root,
        transactions_root: block_header.transactions_root(),
        receipts_root: block_header.receipts_root(),
        logs_bloom,
        difficulty: block_header.difficulty(),
        number: block_header.number(),
        gas_limit: block_header.gas_limit(),
        gas_used: block_header.gas_used(),
        timestamp: block_header.timestamp(),
        extra_data: block_header.extra_data().clone(),
        mix_hash: block_header.mix_hash().unwrap(),
        nonce: block_header.nonce().unwrap(),
        base_fee_per_gas: block_header.base_fee_per_gas(),
        withdrawals_root: block_header.withdrawals_root(),
        blob_gas_used: block_header.blob_gas_used(),
        excess_blob_gas: block_header.excess_blob_gas(),
        parent_beacon_block_root: block_header.parent_beacon_block_root(),
        requests_hash: block_header.requests_hash(),
        block_access_list_hash: None,
        slot_number: None,
    }
}

fn verify_header_hash(
    derived: &Header,
    original: &(impl BlockHeader + Sealable),
) -> Result<(), HostError> {
    let constructed = derived.hash_slow();
    let expected = original.hash_slow();
    if constructed != expected {
        return Err(HostError::HeaderMismatch(constructed, expected));
    }
    Ok(())
}
