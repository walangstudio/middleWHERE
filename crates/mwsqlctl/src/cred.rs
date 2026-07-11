//! Credential CRUD — thin offline wrappers over [`mw_core::mutate`]. Each
//! credential pairs a backend username with a backend password; multiple envs
//! may share one credential row (single rotation). The mutation logic lives in
//! mw-core so the daemon shares it; this module keeps load/save glue plus the
//! read/render helpers.

use std::path::Path;

use anyhow::Result;

use mw_core::config::Config;
use mw_core::secret::SecretStr;
use mw_core::state::KeystoreChoice;

use crate::store::with_config;

pub fn add(
    state_dir: &Path,
    ks: &KeystoreChoice,
    name: &str,
    backend_user: &str,
    password: SecretStr,
) -> Result<()> {
    with_config(state_dir, ks, |cfg| {
        mw_core::mutate::add_cred(cfg, name, backend_user, password)
    })
}

pub fn rotate(
    state_dir: &Path,
    ks: &KeystoreChoice,
    name: &str,
    new_password: SecretStr,
) -> Result<()> {
    with_config(state_dir, ks, |cfg| {
        mw_core::mutate::rotate_cred(cfg, name, new_password)
    })
}

pub fn rm(state_dir: &Path, ks: &KeystoreChoice, name: &str) -> Result<()> {
    with_config(state_dir, ks, |cfg| mw_core::mutate::rm_cred(cfg, name))
}

#[derive(Debug, Clone)]
pub struct CredRow {
    pub name: String,
    pub backend_user: String,
}

pub fn list(state_dir: &Path, ks: &KeystoreChoice) -> Result<Vec<CredRow>> {
    Ok(rows(&mw_core::state::load_config(state_dir, ks)?))
}

/// Build the credential rows from an already-unsealed config. See
/// [`crate::bastion::rows`] — lets the wizard unseal once for all three lists.
pub fn rows(cfg: &Config) -> Vec<CredRow> {
    cfg.credentials
        .iter()
        .map(|(name, c)| CredRow {
            name: name.clone(),
            backend_user: c.backend_user.clone(),
        })
        .collect()
}
