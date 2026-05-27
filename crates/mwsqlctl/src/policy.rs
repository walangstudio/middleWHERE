//! Policy toggle for a single env. ReadOnly → ReadWrite requires the
//! `--i-know-what-im-doing` confirmation flag. This is the only path
//! mwsqlctl provides to relax the default deny-write posture, by design.

use std::path::Path;

use anyhow::{anyhow, bail, Result};

use mw_core::config::Policy;
use mw_core::state::KeystoreChoice;

use crate::store::with_config;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyTarget {
    ReadOnly,
    ReadWrite,
}

pub fn set(
    state_dir: &Path,
    ks: &KeystoreChoice,
    env_name: &str,
    target: PolicyTarget,
    confirm_unsafe: bool,
) -> Result<()> {
    if target == PolicyTarget::ReadWrite && !confirm_unsafe {
        bail!("ReadWrite requires --i-know-what-im-doing");
    }
    with_config(state_dir, ks, |cfg| {
        let env = cfg
            .envs
            .get_mut(env_name)
            .ok_or_else(|| anyhow!("env {:?} not found", env_name))?;
        env.policy = match target {
            PolicyTarget::ReadOnly => Policy::ReadOnly,
            PolicyTarget::ReadWrite => Policy::ReadWrite,
        };
        Ok(())
    })
}
