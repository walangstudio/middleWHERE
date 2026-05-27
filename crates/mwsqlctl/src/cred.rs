//! Credential CRUD. Each credential pairs a backend username with a backend
//! password. Multiple envs may share one credential row (single rotation);
//! envs can also reference distinct credentials that happen to share a
//! backend username with different passwords — the schema makes this trivial.

use std::path::Path;

use anyhow::{anyhow, bail, Result};

use mw_core::config::Credential;
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
        if cfg.credentials.contains_key(name) {
            bail!("credential {:?} already exists", name);
        }
        cfg.credentials.insert(
            name.to_string(),
            Credential {
                backend_user: backend_user.to_string(),
                backend_password: password,
            },
        );
        Ok(())
    })
}

pub fn rotate(
    state_dir: &Path,
    ks: &KeystoreChoice,
    name: &str,
    new_password: SecretStr,
) -> Result<()> {
    with_config(state_dir, ks, |cfg| {
        let cred = cfg
            .credentials
            .get_mut(name)
            .ok_or_else(|| anyhow!("credential {:?} not found", name))?;
        cred.backend_password = new_password;
        Ok(())
    })
}

pub fn rm(state_dir: &Path, ks: &KeystoreChoice, name: &str) -> Result<()> {
    with_config(state_dir, ks, |cfg| {
        let users: Vec<&str> = cfg
            .envs
            .iter()
            .filter(|(_, e)| e.credential == name)
            .map(|(n, _)| n.as_str())
            .collect();
        if !users.is_empty() {
            return Err(anyhow!(
                "credential {:?} is still referenced by env(s): {}",
                name,
                users.join(", ")
            ));
        }
        if cfg.credentials.remove(name).is_none() {
            bail!("credential {:?} not found", name);
        }
        Ok(())
    })
}

#[derive(Debug, Clone)]
pub struct CredRow {
    pub name: String,
    pub backend_user: String,
}

pub fn list(state_dir: &Path, ks: &KeystoreChoice) -> Result<Vec<CredRow>> {
    let cfg = mw_core::state::load_config(state_dir, ks)?;
    Ok(cfg
        .credentials
        .iter()
        .map(|(name, c)| CredRow {
            name: name.clone(),
            backend_user: c.backend_user.clone(),
        })
        .collect())
}
