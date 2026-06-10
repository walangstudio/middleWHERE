//! `mwsqlctl` library. All real work lives here so tests can drive each
//! mutation without spawning a subprocess. The bin is a thin clap wrapper.
//!
//! Concurrency: every public function in this crate is synchronous and
//! reads + writes the sealed config once. Long-term, the same surface will
//! gain an "online" counterpart that talks to a running daemon over IPC
//! (Phase 6b in the plan); today, offline-only.

pub mod audit_tail;
pub mod bastion;
pub mod cred;
pub mod envs;
pub mod import_poc;
pub mod init;
pub mod installer;
pub mod ops;
pub mod policy;
pub(crate) mod prompt;
pub(crate) mod service;
pub mod store;
pub mod wizard;
