//! Ethereum EVM implementation.

use alloy_consensus::{Header, TxType};
use alloy_evm::{
    block::{
        BlockExecutionError, BlockExecutionResult, BlockExecutor, BlockExecutorFactory, GasOutput,
        OnStateHook, StateDB,
    },
    env::EvmEnv,
    eth::{EthBlockExecutionCtx, EthBlockExecutor, EthTxResult},
    evm::EvmFactory,
    precompiles::PrecompilesMap,
    Database, Evm,
};
use alloy_primitives::{Address, Bytes};
use core::{
    fmt::Debug,
    ops::{Deref, DerefMut},
};
use std::{convert::Infallible, sync::Arc};

use fluentbase_revm::{
    revm::{
        context::{BlockEnv, CfgEnv, TxEnv},
        context_interface::result::{EVMError, HaltReason, ResultAndState},
        handler::{instructions::EthInstructions, EthPrecompiles, PrecompileProvider},
        inspector::NoOpInspector,
        interpreter::{interpreter::EthInterpreter, InterpreterResult},
        primitives::hardfork::SpecId,
        Context, ExecuteEvm, InspectEvm, Inspector, SystemCallEvm,
    },
    DefaultRwasm, RwasmBuilder, RwasmEvm, RwasmFrame, RwasmPrecompiles,
};

use reth_chainspec::ChainSpec;
use reth_ethereum_primitives::{EthPrimitives, Receipt, TransactionSigned};
use reth_evm::{block::ExecutableTx, ConfigureEvm, EvmEnvFor, NextBlockEnvAttributes};
use reth_evm_ethereum::{EthBlockAssembler, EthEvmConfig, RethReceiptBuilder};
use reth_primitives_traits::{BlockTy, SealedBlock, SealedHeader};

/// The Ethereum EVM context type.
pub type EthRwasmContext<DB> = Context<BlockEnv, TxEnv, CfgEnv, DB>;

/// Ethereum EVM implementation.
#[expect(missing_debug_implementations)]
pub struct FluentEvmExecutor<DB: Database, I, PRECOMPILE = EthPrecompiles> {
    inner: RwasmEvm<
        EthRwasmContext<DB>,
        I,
        EthInstructions<EthInterpreter, EthRwasmContext<DB>>,
        PRECOMPILE,
        RwasmFrame,
    >,
    inspect: bool,
}

impl<DB: Database, I, PRECOMPILE> FluentEvmExecutor<DB, I, PRECOMPILE> {
    pub const fn new(
        evm: RwasmEvm<
            EthRwasmContext<DB>,
            I,
            EthInstructions<EthInterpreter, EthRwasmContext<DB>>,
            PRECOMPILE,
        >,
        inspect: bool,
    ) -> Self {
        Self { inner: evm, inspect }
    }

    pub fn into_inner(
        self,
    ) -> RwasmEvm<
        EthRwasmContext<DB>,
        I,
        EthInstructions<EthInterpreter, EthRwasmContext<DB>>,
        PRECOMPILE,
        RwasmFrame,
    > {
        self.inner
    }

    pub fn ctx(&self) -> &EthRwasmContext<DB> {
        &self.inner.0.ctx
    }

    pub fn ctx_mut(&mut self) -> &mut EthRwasmContext<DB> {
        &mut self.inner.0.ctx
    }
}

impl<DB: Database, I, PRECOMPILE> Deref for FluentEvmExecutor<DB, I, PRECOMPILE> {
    type Target = EthRwasmContext<DB>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.ctx()
    }
}

impl<DB: Database, I, PRECOMPILE> DerefMut for FluentEvmExecutor<DB, I, PRECOMPILE> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.ctx_mut()
    }
}

impl<DB, I, PRECOMPILE> Evm for FluentEvmExecutor<DB, I, PRECOMPILE>
where
    DB: Database,
    I: Inspector<EthRwasmContext<DB>>,
    PRECOMPILE: PrecompileProvider<EthRwasmContext<DB>, Output = InterpreterResult>,
{
    type DB = DB;
    type Tx = TxEnv;
    type Error = EVMError<DB::Error>;
    type HaltReason = HaltReason;
    type Spec = SpecId;
    type BlockEnv = BlockEnv;
    type Precompiles = PRECOMPILE;
    type Inspector = I;

    fn block(&self) -> &BlockEnv {
        &self.block
    }

    fn cfg_env(&self) -> &CfgEnv<Self::Spec> {
        &self.cfg
    }

    fn chain_id(&self) -> u64 {
        self.cfg.chain_id
    }

    fn transact_raw(&mut self, tx: Self::Tx) -> Result<ResultAndState, Self::Error> {
        if self.inspect {
            self.inner.inspect_tx(tx)
        } else {
            self.inner.transact(tx)
        }
    }

    fn transact_system_call(
        &mut self,
        caller: Address,
        contract: Address,
        data: Bytes,
    ) -> Result<ResultAndState, Self::Error> {
        self.inner.system_call_with_caller(caller, contract, data)
    }

    fn db_mut(&mut self) -> &mut Self::DB {
        &mut self.journaled_state.database
    }

    fn finish(self) -> (Self::DB, EvmEnv<Self::Spec>) {
        let Context { block: block_env, cfg: cfg_env, journaled_state, .. } = self.inner.0.ctx;

        (journaled_state.database, EvmEnv { block_env, cfg_env })
    }

    fn set_inspector_enabled(&mut self, enabled: bool) {
        self.inspect = enabled;
    }

    fn precompiles(&self) -> &Self::Precompiles {
        &self.inner.0.precompiles
    }

    fn precompiles_mut(&mut self) -> &mut Self::Precompiles {
        &mut self.inner.0.precompiles
    }

    fn inspector(&self) -> &Self::Inspector {
        &self.inner.0.inspector
    }

    fn inspector_mut(&mut self) -> &mut Self::Inspector {
        &mut self.inner.0.inspector
    }

    fn components(&self) -> (&Self::DB, &Self::Inspector, &Self::Precompiles) {
        (
            &self.inner.0.ctx.journaled_state.database,
            &self.inner.0.inspector,
            &self.inner.0.precompiles,
        )
    }

    fn components_mut(&mut self) -> (&mut Self::DB, &mut Self::Inspector, &mut Self::Precompiles) {
        (
            &mut self.inner.0.ctx.journaled_state.database,
            &mut self.inner.0.inspector,
            &mut self.inner.0.precompiles,
        )
    }
}

/// Factory producing [`FluentEvmExecutor`].
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct FluentEvmFactory;

impl EvmFactory for FluentEvmFactory {
    type Evm<DB: Database, I: Inspector<EthRwasmContext<DB>>> =
        FluentEvmExecutor<DB, I, Self::Precompiles>;
    type Context<DB: Database> = Context<BlockEnv, TxEnv, CfgEnv, DB>;
    type Tx = TxEnv;
    type Error<DBError: core::error::Error + Send + Sync + 'static> = EVMError<DBError>;
    type HaltReason = HaltReason;
    type Spec = SpecId;
    type BlockEnv = BlockEnv;
    type Precompiles = PrecompilesMap;

    fn create_evm<DB: Database>(&self, db: DB, input: EvmEnv) -> Self::Evm<DB, NoOpInspector> {
        let spec_id = input.cfg_env.spec;
        FluentEvmExecutor {
            inner: Context::rwasm()
                .with_block(input.block_env)
                .with_cfg(input.cfg_env)
                .with_db(db)
                .build_rwasm_with_inspector(NoOpInspector {})
                .with_precompiles(PrecompilesMap::from_static(
                    RwasmPrecompiles::new_with_spec(spec_id).precompiles(),
                )),
            inspect: false,
        }
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>>>(
        &self,
        db: DB,
        input: EvmEnv,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        let spec_id = input.cfg_env.spec;
        FluentEvmExecutor {
            inner: Context::rwasm()
                .with_block(input.block_env)
                .with_cfg(input.cfg_env)
                .with_db(db)
                .build_rwasm_with_inspector(inspector)
                .with_precompiles(PrecompilesMap::from_static(
                    RwasmPrecompiles::new_with_spec(spec_id).precompiles(),
                )),
            inspect: true,
        }
    }
}

// ============================================================================
// Block Execution and Configuration (Moved from fleutn evm)
// ============================================================================

#[derive(Debug, Clone)]
pub struct FluentEvmConfig {
    /// Inner evm config
    pub inner: EthEvmConfig<ChainSpec, FluentEvmFactory>,
}
impl FluentEvmConfig {
    /// Create a new [`TempoEvmConfig`] with the given chain spec and EVM factory.
    pub fn new(chain_spec: Arc<ChainSpec>, evm_factory: FluentEvmFactory) -> Self {
        let inner = EthEvmConfig::new_with_evm_factory(chain_spec.clone(), evm_factory);
        Self { inner }
    }
    /// Create a new [`TempoEvmConfig`] with the given chain spec and default EVM factory.
    pub fn new_with_default_factory(chain_spec: Arc<ChainSpec>) -> Self {
        Self::new(chain_spec, FluentEvmFactory::default())
    }
    /// Returns the chain spec
    pub const fn chain_spec(&self) -> &Arc<ChainSpec> {
        self.inner.chain_spec()
    }
    /// Returns the inner EVM config
    pub const fn inner(&self) -> &EthEvmConfig<ChainSpec, FluentEvmFactory> {
        &self.inner
    }
}

impl BlockExecutorFactory for FluentEvmConfig {
    type EvmFactory = FluentEvmFactory;
    type TxExecutionResult = EthTxResult<HaltReason, TxType>;
    type ExecutionCtx<'a> = EthBlockExecutionCtx<'a>;
    type Transaction = TransactionSigned;
    type Receipt = Receipt;
    type Executor<'a, DB: StateDB, I: Inspector<<Self::EvmFactory as EvmFactory>::Context<DB>>> =
        FluentBlockExecutor<'a, FluentEvmExecutor<DB, I, PrecompilesMap>>;
    fn evm_factory(&self) -> &Self::EvmFactory {
        self.inner.evm_factory()
    }
    fn create_executor<'a, DB, I>(
        &'a self,
        evm: FluentEvmExecutor<DB, I, PrecompilesMap>,
        ctx: EthBlockExecutionCtx<'a>,
    ) -> Self::Executor<'a, DB, I>
    where
        DB: StateDB,
        I: Inspector<<Self::EvmFactory as EvmFactory>::Context<DB>>,
    {
        FluentBlockExecutor {
            inner: EthBlockExecutor::new(
                evm,
                ctx,
                self.inner.chain_spec(),
                self.inner.executor_factory.receipt_builder(),
            ),
        }
    }
}

impl ConfigureEvm for FluentEvmConfig {
    type Primitives = EthPrimitives;
    type Error = Infallible;
    type NextBlockEnvCtx = NextBlockEnvAttributes;
    type BlockExecutorFactory = Self;
    type BlockAssembler = EthBlockAssembler<ChainSpec>;
    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        self
    }
    fn block_assembler(&self) -> &Self::BlockAssembler {
        self.inner.block_assembler()
    }
    fn evm_env(&self, header: &Header) -> Result<EvmEnvFor<Self>, Self::Error> {
        self.inner.evm_env(header)
    }
    fn next_evm_env(
        &self,
        parent: &Header,
        attributes: &Self::NextBlockEnvCtx,
    ) -> Result<EvmEnvFor<Self>, Self::Error> {
        self.inner.next_evm_env(parent, attributes)
    }
    fn context_for_block<'a>(
        &self,
        block: &'a SealedBlock<BlockTy<Self::Primitives>>,
    ) -> Result<EthBlockExecutionCtx<'a>, Self::Error> {
        self.inner.context_for_block(block)
    }
    fn context_for_next_block(
        &self,
        parent: &SealedHeader<Header>,
        attributes: Self::NextBlockEnvCtx,
    ) -> Result<EthBlockExecutionCtx<'_>, Self::Error> {
        self.inner.context_for_next_block(parent, attributes)
    }
}

#[derive(Debug)]
pub struct FluentBlockExecutor<'a, Evm> {
    /// Inner Ethereum execution strategy.
    inner: EthBlockExecutor<'a, Evm, &'a Arc<ChainSpec>, &'a RethReceiptBuilder>,
}

impl<'a, E> BlockExecutor for FluentBlockExecutor<'a, E>
where
    E: Evm<Tx = TxEnv>,
    EthBlockExecutor<'a, E, &'a Arc<ChainSpec>, &'a RethReceiptBuilder>: BlockExecutor<
        Transaction = TransactionSigned,
        Receipt = Receipt,
        Evm = E,
        Result = EthTxResult<E::HaltReason, TxType>,
    >,
{
    type Transaction = TransactionSigned;
    type Receipt = Receipt;
    type Evm = E;
    type Result = EthTxResult<E::HaltReason, TxType>;
    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        // Note: Ideally, this shouldn't be required if there are no memory leaks, but supporting a
        //  memory allocator inside virtual runtime brings overhead.
        // Instead, we can just re-create the store to make sure all data is pruned.
        fluentbase_runtime::runtime::SystemRuntime::reset_cached_runtimes();
        // Invoke parent method
        self.inner.apply_pre_execution_changes()
    }
    fn execute_transaction_without_commit(
        &mut self,
        tx: impl ExecutableTx<Self>,
    ) -> Result<Self::Result, BlockExecutionError> {
        self.inner.execute_transaction_without_commit(tx)
    }
    fn commit_transaction(&mut self, output: Self::Result) -> GasOutput {
        self.inner.commit_transaction(output)
    }
    fn finish(self) -> Result<(Self::Evm, BlockExecutionResult<Receipt>), BlockExecutionError> {
        self.inner.finish()
    }
    fn set_state_hook(&mut self, _hook: Option<Box<dyn OnStateHook>>) {
        self.inner.set_state_hook(_hook)
    }
    fn evm_mut(&mut self) -> &mut Self::Evm {
        self.inner.evm_mut()
    }
    fn evm(&self) -> &Self::Evm {
        self.inner.evm()
    }
    fn receipts(&self) -> &[Self::Receipt] {
        self.inner.receipts()
    }
}
