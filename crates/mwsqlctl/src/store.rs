//! Load → mutate → save harness. Used by every CRUD subcommand so the
//! atomic-write + validation + backup behaviour is enforced uniformly.

use std::path::Path;

use anyhow::Result;

use mw_core::config::Config;
use mw_core::state::{load_config, save_config, KeystoreChoice};

pub fn with_config<F, R>(state_dir: &Path, ks: &KeystoreChoice, mutate: F) -> Result<R>
where
    F: FnOnce(&mut Config) -> Result<R>,
{
    let mut cfg = load_config(state_dir, ks)?;
    let out = mutate(&mut cfg)?;
    save_config(state_dir, ks, &cfg)?;
    Ok(out)
}
