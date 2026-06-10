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

/// Run a config-touching `mwsqlctl` command, auto-elevating on Windows service
/// mode so it does not just fail against the admin-locked state dir. The bin
/// wraps its command dispatch (everything except the self-elevating `init` /
/// `wizard`) in this.
pub fn run_elevated_or<F: FnOnce() -> anyhow::Result<()>>(
    service: bool,
    uac: bool,
    needs_config: bool,
    run: F,
) -> anyhow::Result<()> {
    crate::service::run_elevated_or(service, uac, needs_config, run)
}
