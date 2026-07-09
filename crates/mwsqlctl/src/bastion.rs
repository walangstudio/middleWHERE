//! Bastion CRUD. Add stores password or PEM-encoded private key directly into
//! the sealed config; the cleartext key never touches `secrets/` — it goes
//! straight into the AEAD blob.

use std::path::Path;

use anyhow::{anyhow, bail, Result};

use mw_core::config::{Bastion, BastionAuth, HostKeyFingerprint};
use mw_core::secret::{SecretBytes, SecretStr};
use mw_core::state::KeystoreChoice;

use crate::store::with_config;

pub enum BastionAuthInput {
    Password(SecretStr),
    Key {
        pem: SecretBytes,
        passphrase: Option<SecretStr>,
    },
}

pub struct BastionAddArgs<'a> {
    pub name: &'a str,
    pub host: &'a str,
    pub port: u16,
    pub ssh_user: &'a str,
    pub auth: BastionAuthInput,
    pub fingerprint: Option<HostKeyFingerprint>,
}

pub fn add(state_dir: &Path, ks: &KeystoreChoice, args: BastionAddArgs<'_>) -> Result<()> {
    with_config(state_dir, ks, |cfg| {
        if cfg.bastions.contains_key(args.name) {
            bail!("bastion {:?} already exists", args.name);
        }
        let auth = match args.auth {
            BastionAuthInput::Password(p) => BastionAuth::Password { password: p },
            BastionAuthInput::Key { pem, passphrase } => BastionAuth::Key {
                private_key_pem: pem,
                passphrase,
            },
        };
        cfg.bastions.insert(
            args.name.to_string(),
            Bastion {
                host: args.host.to_string(),
                port: args.port,
                ssh_user: args.ssh_user.to_string(),
                auth,
                pinned_host_keys: args.fingerprint.into_iter().collect(),
            },
        );
        Ok(())
    })
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
        let b = cfg
            .bastions
            .get_mut(name)
            .ok_or_else(|| anyhow!("bastion {name:?} not found"))?;
        b.pinned_host_keys = vec![fingerprint];
        Ok(())
    })
}

pub fn rm(state_dir: &Path, ks: &KeystoreChoice, name: &str) -> Result<()> {
    with_config(state_dir, ks, |cfg| {
        let users: Vec<&str> = cfg
            .envs
            .iter()
            .filter(|(_, e)| e.bastion.as_deref() == Some(name))
            .map(|(n, _)| n.as_str())
            .collect();
        if !users.is_empty() {
            return Err(anyhow!(
                "bastion {:?} is still referenced by env(s): {}",
                name,
                users.join(", ")
            ));
        }
        if cfg.bastions.remove(name).is_none() {
            bail!("bastion {:?} not found", name);
        }
        Ok(())
    })
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
    let cfg = mw_core::state::load_config(state_dir, ks)?;
    Ok(cfg
        .bastions
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
        .collect())
}
