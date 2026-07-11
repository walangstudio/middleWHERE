//! Policy toggle for a single env. ReadOnly → ReadWrite requires the
//! `--i-know-what-im-doing` confirmation flag. This is the only path
//! mwsqlctl provides to relax the default deny-write posture, by design.
//! The field rewrite lives in [`mw_core::mutate::set_policy`]; the confirmation
//! gate stays here so the offline path fails before touching the keystore.

use std::path::Path;

use anyhow::{bail, Result};

use mw_core::state::KeystoreChoice;

use crate::store::with_config;

pub use mw_core::mutate::PolicyTarget;

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
        mw_core::mutate::set_policy(cfg, env_name, target)
    })
}
