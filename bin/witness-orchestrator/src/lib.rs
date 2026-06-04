// Hybrid lib+bin: exposing orchestrator internals as `pub` for
// in-tree consumers (sp1-executor-canary). Workspace lints
// `missing_debug_implementations` and `unreachable_pub` would
// otherwise fire on every newly-pub item — silencing them at the
// lib root keeps the bin target's lints fully live (the bin
// declares its own `#![allow(unreachable_pub)]` for the
// `crate::*` self-references).
#![allow(missing_debug_implementations, unreachable_pub, dead_code)]

//! Library entry-point for `witness-orchestrator-bin`. Exposes the
//! reusable internals (forward-sync driver, witness hub, MDBX-backed
//! blob builder, events-hash helpers, shared types) so in-tree
//! consumers — currently `bin/sp1-executor-canary` — can depend on
//! them without re-implementing the forward-sync stack.
//!
//! The `witness-orchestrator` daemon binary lives at `src/main.rs`
//! and continues to reference these modules via `crate::*` paths.
//! External consumers reach them through `witness_orchestrator::*`.
//!
//! Modules NOT re-exported here are orchestrator-internal: SQLite
//! schema (`db`, `challenge_db`), L1 listener (`l1_listener`), RBF
//! dispatch (`rbf`), batch lifecycle (`orchestrator`), challenge
//! resolver (`challenge_resolver`), block-response cache, metrics
//! registry. None of them are useful to a canary; keeping them
//! private avoids accidentally turning orchestrator-internal helpers
//! into a forever-stable public surface.

pub mod blob_builder_mdbx;
pub mod driver;
pub mod events_hash_reth;
pub mod hub;
pub mod types;

// Orchestrator-internal modules. They compile inside the lib target
// because exposed code (`driver::Driver`) transitively references them
// (e.g. `crate::metrics::*`, `crate::orchestrator::RevertKind`). Kept
// `pub(crate)` so external consumers can't import them.
pub(crate) mod block_response_cache;
pub(crate) mod cert_source;
pub(crate) mod challenge_db;
pub(crate) mod challenge_resolver;
pub(crate) mod db;
pub(crate) mod l1_listener;
pub(crate) mod metrics;
pub(crate) mod orchestrator;
pub(crate) mod rbf;
