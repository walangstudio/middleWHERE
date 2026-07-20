//! `mwsqlctl uninstall` — tear down a deployment: the inverse of `init`.
//!
//! Service mode (the default) self-elevates, stops + removes the OS service, and
//! deletes the sealed config, master key, and audit log. `--user` removes the
//! per-user deployment with no elevation and no service. It is destructive and
//! irreversible — every credential, bastion, env token-hash, and the audit trail
//! go with the state dir — so it confirms first unless `--yes` is given.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use mw_core::state::{default_state_dir, resolve_cli_target};

use crate::prompt::confirm;
use crate::service;

/// The raw flags `uninstall` resolves its mode and elevation from.
pub struct UninstallOpts {
    pub state_dir: Option<PathBuf>,
    pub user: bool,
    pub file_keystore: bool,
    /// systemd unit / Windows service name to remove (service mode).
    pub service_name: String,
    /// Skip the confirmation prompt (required for non-interactive runs).
    pub yes: bool,
    /// Set on the Windows UAC-relaunched child: don't re-elevate, and pause
    /// before the (new) console closes so the result stays readable.
    pub uac: bool,
}

pub fn run(opts: UninstallOpts) -> Result<()> {
    // Mirror `init`: the Windows elevated child runs in a throwaway console that
    // vanishes on exit, so pause on the way out (only with a real terminal, so a
    // piped `--uac` run never hangs).
    let uac = cfg!(windows) && opts.uac;
    let result = run_inner(opts);
    if uac && std::io::stdin().is_terminal() {
        if let Err(e) = &result {
            eprintln!("\nError: {e:#}");
        }
        let _ = crate::prompt::read_line("\nDone. Press Enter to close this window:");
        return Ok(());
    }
    result
}

fn run_inner(opts: UninstallOpts) -> Result<()> {
    let service = !opts.user;

    if service {
        service::validate_service_name(&opts.service_name)?;
    }

    // Removing the service and the root/Admin-owned state dir needs elevation.
    // Elevate-first, exactly like `init`: `sudo` re-exec on Linux, a UAC relaunch
    // on Windows.
    if service && service::needs_service_elevation(opts.uac) {
        let forward = forwarded_args(&opts);
        let target_dir = opts.state_dir.clone().unwrap_or_else(default_state_dir);
        let reason = format!(
            "Uninstalling needs root: it stops and removes the {svc} service and \
             deletes {dir} (config, master key, audit log).",
            svc = opts.service_name,
            dir = target_dir.display(),
        );
        return service::elevate_for_service("uninstall", &forward, &reason);
    }

    let (state_dir, ks) = resolve_cli_target(opts.state_dir.clone(), opts.user, opts.file_keystore);

    // Destructive + irreversible: confirm unless --yes. With no terminal to
    // confirm on, refuse rather than wipe a deployment unattended.
    if !opts.yes {
        println!("This permanently removes:");
        if service {
            println!("  - the {} service", opts.service_name);
        }
        println!(
            "  - {} (sealed config, master key, audit log)",
            state_dir.display()
        );
        if !std::io::stdin().is_terminal() {
            bail!("refusing to uninstall without confirmation; pass --yes");
        }
        if !confirm("Continue?", false)? {
            println!("Aborted. Nothing was removed.");
            return Ok(());
        }
    }

    // Stop the service first so it releases any handle on the state dir.
    if service {
        service::uninstall_service(&opts.service_name)?;
    }

    // Remove the state dir BEFORE clearing the keystore: never destroy the master
    // key while the sealed config it protects still exists, so a failed removal
    // stays recoverable. The file backend's key lives inside the dir and goes with
    // it; clearing the keystore afterwards drops the OS-keychain entry (and is a
    // tolerated no-op for the already-gone file key). The keystore delete runs
    // even when no dir was present, so a pre-removed deployment leaves no dangling
    // keychain entry.
    let removed = remove_state_dir(&state_dir)?;
    ks.delete()?;

    if removed {
        println!("Uninstalled. Removed {}.", state_dir.display());
    } else if service {
        println!(
            "Removed the {} service; no config was present at {}.",
            opts.service_name,
            state_dir.display()
        );
    } else {
        println!("Nothing to remove at {}.", state_dir.display());
    }
    Ok(())
}

/// Remove the state dir if present. Returns whether it existed, so the caller can
/// distinguish a real teardown from a no-op.
fn remove_state_dir(dir: &Path) -> Result<bool> {
    if dir.exists() {
        std::fs::remove_dir_all(dir).with_context(|| format!("remove {}", dir.display()))?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Non-secret flags to forward across the sudo / UAC re-exec. Never `--user`
/// (service mode only); carries `--yes` so the elevated run does not re-prompt
/// when the operator already confirmed at the call site by passing it.
fn forwarded_args(opts: &UninstallOpts) -> Vec<OsString> {
    let mut v: Vec<OsString> = Vec::new();
    if let Some(sd) = &opts.state_dir {
        v.push("--state-dir".into());
        v.push(sd.as_os_str().to_owned());
    }
    if opts.file_keystore {
        v.push("--file-keystore".into());
    }
    v.push("--service-name".into());
    v.push(opts.service_name.clone().into());
    if opts.yes {
        v.push("--yes".into());
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> UninstallOpts {
        UninstallOpts {
            state_dir: Some(PathBuf::from("/var/lib/middlewhere")),
            user: false,
            file_keystore: true,
            service_name: "mwsqld".into(),
            yes: true,
            uac: false,
        }
    }

    #[test]
    fn forwarded_args_never_include_user_and_carry_service_flags() {
        let fwd: Vec<String> = forwarded_args(&opts())
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert!(
            !fwd.iter().any(|a| a == "--user"),
            "must not forward --user"
        );
        assert!(fwd.contains(&"--state-dir".to_string()));
        assert!(fwd.contains(&"/var/lib/middlewhere".to_string()));
        assert!(fwd.contains(&"--file-keystore".to_string()));
        assert!(fwd.contains(&"--service-name".to_string()));
        assert!(fwd.contains(&"mwsqld".to_string()));
        assert!(fwd.contains(&"--yes".to_string()));
    }

    #[test]
    fn forwarded_args_minimal_when_no_overrides() {
        let o = UninstallOpts {
            state_dir: None,
            user: false,
            file_keystore: false,
            service_name: "mwsqld".into(),
            yes: false,
            uac: false,
        };
        let fwd: Vec<String> = forwarded_args(&o)
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            fwd,
            vec!["--service-name".to_string(), "mwsqld".to_string()]
        );
    }

    #[test]
    fn remove_state_dir_is_idempotent_and_recursive() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("state");
        std::fs::create_dir_all(dir.join("audit")).unwrap();
        std::fs::write(dir.join("config.sealed"), b"x").unwrap();
        std::fs::write(dir.join("master.key"), b"k").unwrap();

        assert!(
            remove_state_dir(&dir).unwrap(),
            "first removal reports the dir existed"
        );
        assert!(!dir.exists(), "state dir should be gone");
        // Second call on an absent dir is a no-op that reports nothing removed.
        assert!(!remove_state_dir(&dir).unwrap());
    }
}
