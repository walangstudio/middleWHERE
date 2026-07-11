//! Env CRUD + token lifecycle — thin offline wrappers over
//! [`mw_core::mutate`]. The transforms (token minting, port picking, ref
//! checks) live in mw-core so the daemon applies the exact same logic online;
//! this module keeps only load/save glue plus the read/render helpers the CLI
//! and wizard use.

use std::path::Path;

use anyhow::Result;

use mw_core::config::{Config, EngineKind, Policy};
use mw_core::state::KeystoreChoice;

use crate::store::with_config;

pub use mw_core::mutate::{EnvAddArgs, NewEnvOutput};

pub fn add(state_dir: &Path, ks: &KeystoreChoice, args: EnvAddArgs<'_>) -> Result<NewEnvOutput> {
    with_config(state_dir, ks, |cfg| mw_core::mutate::add_env(cfg, args))
}

pub fn rm(state_dir: &Path, ks: &KeystoreChoice, name: &str) -> Result<()> {
    with_config(state_dir, ks, |cfg| mw_core::mutate::rm_env(cfg, name))
}

/// Rotate the env token and return it together with the env's listen port,
/// so the operator can hand a client identity everything `mwsql login`
/// needs. Rotation invalidates the previous token — one env, one live token,
/// delivered to one place.
pub fn grant(state_dir: &Path, ks: &KeystoreChoice, name: &str) -> Result<NewEnvOutput> {
    with_config(state_dir, ks, |cfg| mw_core::mutate::grant_env(cfg, name))
}

#[derive(Debug, Clone)]
pub struct EnvRow {
    pub name: String,
    pub backend: String,
    pub bastion: Option<String>,
    pub credential: String,
    pub policy: &'static str,
    pub listen_port: u16,
    pub engine: &'static str,
}

pub fn list(state_dir: &Path, ks: &KeystoreChoice) -> Result<Vec<EnvRow>> {
    Ok(rows(&mw_core::state::load_config(state_dir, ks)?))
}

/// Build the env rows from an already-unsealed config. See
/// [`crate::bastion::rows`] — lets the wizard unseal once for all three lists.
pub fn rows(cfg: &Config) -> Vec<EnvRow> {
    cfg.envs
        .iter()
        .map(|(name, e)| EnvRow {
            name: name.clone(),
            backend: format!("{}:{}", e.backend_host, e.backend_port),
            bastion: e.bastion.clone(),
            credential: e.credential.clone(),
            policy: policy_label(&e.policy),
            listen_port: e.listen_port,
            engine: engine_label(e.engine),
        })
        .collect()
}

pub fn engine_label(e: EngineKind) -> &'static str {
    match e {
        EngineKind::MySql => "mysql",
        EngineKind::Postgres => "postgres",
        EngineKind::MsSql => "mssql",
    }
}

pub fn policy_label(p: &Policy) -> &'static str {
    match p {
        Policy::ReadOnly => "read-only",
        Policy::ReadWrite => "read-write",
        Policy::Custom { .. } => "custom",
    }
}
