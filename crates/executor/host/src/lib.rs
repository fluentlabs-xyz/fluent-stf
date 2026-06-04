#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use std::sync::Arc;

use fluent_stf_primitives::fluent_chainspec;
use revm_primitives::Address;
use rsp_client_executor::evm::FluentEvmConfig;

pub use error::Error as HostError;
pub use host_executor::{EthHostExecutor, HostExecutor};

mod dpos_witness;
mod error;
pub mod events_hash;
mod host_executor;

pub fn create_eth_block_execution_strategy_factory(
    _custom_beneficiary: Option<Address>,
) -> FluentEvmConfig {
    FluentEvmConfig::new_with_default_factory(Arc::new(fluent_chainspec()))
}
