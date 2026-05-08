//! Local `NodeTypes` binding — matches `reth_node_ethereum::EthereumNode`
//! without pulling in the full `reth-node-ethereum` crate (which
//! transitively depends on `reth-network` → `reth-discv5` and fails
//! Cargo feature unification in this workspace).

use reth_chainspec::ChainSpec;
use reth_ethereum_engine_primitives::EthEngineTypes;
use reth_ethereum_primitives::EthPrimitives;
use reth_node_types::NodeTypes;
use reth_provider::EthStorage;

#[derive(Clone, Debug, Default)]
pub struct FluentMdbxNode;

impl NodeTypes for FluentMdbxNode {
    type Primitives = EthPrimitives;
    type ChainSpec = ChainSpec;
    type Storage = EthStorage;
    type Payload = EthEngineTypes;
}
