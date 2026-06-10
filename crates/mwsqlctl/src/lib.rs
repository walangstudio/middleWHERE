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

/// Print the per-env client token as an unmissable block. The token is shown
/// **once** (only its hash is stored), so it must be impossible to scroll past
/// unnoticed. Used by `env add`, `grant`, and the wizard so the operator always
/// sees the same prominent output.
pub fn print_token_block(env: &str, port: u16, token: &str) {
    let bar = "=".repeat(70);
    println!("\n{bar}");
    println!("  CLIENT TOKEN  —  SAVE NOW (shown only once)");
    println!("{bar}");
    println!("  env:     {env}");
    println!("  token:   {token}");
    println!("  connect: mwsql login {env} --port {port}");
    println!(
        "           any client -> host 127.0.0.1  port {port}  user {env}  \
         password <token>  ssl off"
    );
    println!("{bar}\n");
}

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
