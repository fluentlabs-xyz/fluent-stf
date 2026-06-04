#![cfg_attr(not(test), warn(unused_crate_dependencies))]

/// DPoS block-execution extension (per-block system calls the STF must replay).
pub mod dpos_exec;
/// Client program input data types.
pub mod io;
#[macro_use]
pub mod utils;
pub mod error;
pub mod events_hash;
pub mod evm;
pub mod executor;
pub mod tracking;

mod into_primitives;

pub use into_primitives::{BlockValidator, FromInput, IntoInput, IntoPrimitives};
