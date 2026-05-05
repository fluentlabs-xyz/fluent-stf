//! Embedded forward-sync driver: re-executes L2 blocks against a writable
//! `ProviderFactory` and produces witnesses on demand via
//! `Driver::try_take_new_block`.

mod forward;
mod node_types;

pub(crate) use forward::{open_writable_factory, unwind_to, Driver, DriverConfig};
pub(crate) use node_types::FluentMdbxNode;
