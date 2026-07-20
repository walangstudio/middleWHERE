//! Bastion CRUD — thin offline wrappers over [`mw_core::mutate`]. Add stores a
//! password or PEM-encoded private key directly into the sealed config; the
//! cleartext key never touches `secrets/`. The transforms live in mw-core so
//! the daemon shares them; this module keeps load/save glue plus the
//! read/render helpers.

use std::path::Path;

use anyhow::Result;

use mw_core::config::{BastionAuth, Config, HostKeyFingerprint};
use mw_core::state::KeystoreChoice;

use crate::store::with_config;

pub use mw_core::mutate::{BastionAddArgs, BastionAuthInput};

pub fn add(state_dir: &Path, ks: &KeystoreChoice, args: BastionAddArgs<'_>) -> Result<()> {
    with_config(state_dir, ks, |cfg| mw_core::mutate::add_bastion(cfg, args))
}

/// Replace a bastion's pinned host keys with a single fingerprint. Used by the
/// wizard to pin an unpinned bastion in place, without re-entering its secret.
pub fn set_fingerprint(
    state_dir: &Path,
    ks: &KeystoreChoice,
    name: &str,
    fingerprint: HostKeyFingerprint,
) -> Result<()> {
    with_config(state_dir, ks, |cfg| {
        mw_core::mutate::set_fingerprint(cfg, name, fingerprint)
    })
}

pub fn rm(state_dir: &Path, ks: &KeystoreChoice, name: &str) -> Result<()> {
    with_config(state_dir, ks, |cfg| mw_core::mutate::rm_bastion(cfg, name))
}

#[derive(Debug, Clone)]
pub struct BastionRow {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub ssh_user: String,
    pub auth_kind: &'static str,
    pub pinned_fingerprints: usize,
}

pub fn list(state_dir: &Path, ks: &KeystoreChoice) -> Result<Vec<BastionRow>> {
    Ok(rows(&mw_core::state::load_config(state_dir, ks)?))
}

/// Build the bastion rows from an already-unsealed config, so a caller that
/// needs several listings at once (the wizard's "show current") unseals — and
/// unlocks the OS keychain in `--user` mode — a single time.
pub fn rows(cfg: &Config) -> Vec<BastionRow> {
    cfg.bastions
        .iter()
        .map(|(name, b)| BastionRow {
            name: name.clone(),
            host: b.host.clone(),
            port: b.port,
            ssh_user: b.ssh_user.clone(),
            auth_kind: match &b.auth {
                BastionAuth::Password { .. } => "password",
                BastionAuth::Key { .. } => "key",
            },
            pinned_fingerprints: b.pinned_host_keys.len(),
        })
        .collect()
}
