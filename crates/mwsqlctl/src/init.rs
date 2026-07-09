//! `mwsqlctl init` — bootstrap a deployment.
//!
//! Service mode (the default) installs middleWHERE as a managed service: it
//! self-elevates, creates the `mwsqld` system account, seeds the sealed config,
//! writes the hardened systemd unit, and `enable --now`s it. The daemon comes
//! up idle (no envs yet) and binds nothing until connections are configured.
//! Then it offers to run the connection wizard inline while still elevated.
//!
//! `--user` seeds a per-user config (OS keychain, no service, no elevation) and
//! leaves configuration to the operator — the manual path.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::Result;

use mw_core::state::{default_state_dir, resolve_service_install_target};

use crate::ops::{self, Target};
use crate::prompt::confirm;
use crate::{service, wizard};

/// The raw flags `init` resolves its mode and elevation from.
pub struct InitOpts {
    pub state_dir: Option<PathBuf>,
    pub user: bool,
    pub file_keystore: bool,
    /// systemd unit + system account name (service mode).
    pub service_name: String,
    /// mwsqld binary baked into the unit; defaults to a sibling of this exe.
    pub exec_path: Option<PathBuf>,
    /// Set on the Windows UAC-relaunched child: don't re-elevate, and pause
    /// before the (new) console closes so the one-time token stays readable.
    pub uac: bool,
}

pub fn run(opts: InitOpts) -> Result<()> {
    // The elevated child's stdout/stderr and exit code are mirrored back to the
    // original terminal by the relaunch helper, so there is no throwaway console
    // to pause for here.
    run_inner(opts)
}

fn run_inner(opts: InitOpts) -> Result<()> {
    let service = !opts.user;

    if service {
        // Baked into useradd / chown / User= / the unit path; validate before
        // we touch the system or elevate.
        service::validate_service_name(&opts.service_name)?;
    }

    // Installing a service writes the root-owned/Admin-owned state dir and
    // registers a unit → needs root (Linux) / admin (Windows). Elevate-first
    // before anything else: `sudo` re-exec on Linux, a UAC relaunch on Windows.
    if service && service::needs_service_elevation(opts.uac) {
        let forward = forwarded_args(&opts);
        let target_dir = opts.state_dir.clone().unwrap_or_else(default_state_dir);
        let reason = format!(
            "Installing the service needs root: it creates the {svc} system\n\
             account, writes /etc/systemd/system/{svc}.service, and seeds {dir}.",
            svc = opts.service_name,
            dir = target_dir.display(),
        );
        return service::elevate_for_service("init", &forward, &reason);
    }

    // Service install must never adopt a v0.2.x legacy per-user config: the
    // service account can't reach the installing user's OS keychain to unseal it.
    let (state_dir, ks) =
        resolve_service_install_target(opts.state_dir.clone(), opts.user, opts.file_keystore);
    let t = Target::new(&state_dir, &ks);

    if !service {
        // Per-user: seed config only. Manual configuration from here.
        seed_if_needed(t, &state_dir)?;
        println!("\nConfigure connections with:");
        println!("  mwsqlctl --user wizard      # guided");
        println!("  mwsqld   --user run         # then run it");
        return Ok(());
    }

    // ---- service mode: root on Linux, or print-steps elsewhere ----
    println!("middleWHERE — install service deployment");
    println!("State dir: {} (root-owned)\n", state_dir.display());

    if cfg!(target_os = "linux") && service::is_root() {
        service::ensure_service_user(&opts.service_name)?;
    }

    seed_if_needed(t, &state_dir)?;

    // Hand the freshly seeded files to the service account before the unit
    // starts (the daemon reads them sandboxed).
    if cfg!(target_os = "linux") && service::is_root() {
        service::chown_state_dir(&state_dir, &opts.service_name)?;
    }

    service::install_and_enable_service(&opts.service_name, opts.exec_path.as_deref(), &state_dir)?;

    // The Windows UAC child redirects stdout to a temp file, so its interactive
    // prompts would be invisible — skip the inline wizard there and point at the
    // separate `wizard` command instead.
    let interactive = std::io::stdin().is_terminal() && !(cfg!(windows) && opts.uac);
    offer_configure(t, &opts.service_name, &state_dir, interactive)?;
    Ok(())
}

fn seed_if_needed(t: Target, state_dir: &Path) -> Result<()> {
    if ops::is_initialized(state_dir) {
        // Re-running init is fine: reuse the existing config, just (re)install
        // the unit. The "already exists" refusal is the idempotent signal.
        println!(
            "Config already present at {} — reusing it.",
            state_dir.display()
        );
    } else {
        ops::init(t)?;
        println!("Seeded sealed config at {}.", state_dir.display());
    }
    Ok(())
}

/// While still elevated, offer to configure connections inline (no second
/// sudo). Skipped when there's no terminal — init can run headless for the
/// service install alone.
fn offer_configure(
    t: Target,
    service_name: &str,
    state_dir: &Path,
    interactive: bool,
) -> Result<()> {
    if interactive && confirm("\nConfigure connections now?", true)? {
        let changed = wizard::run_config(t)?;
        wizard::finalize_service_config(service_name, state_dir, changed)?;
    } else {
        println!("\nNext: configure connections with");
        if cfg!(windows) {
            // The wizard needs admin and won't auto-elevate (its prompts can't
            // show in a redirected UAC child), so it must be run already-elevated.
            println!("  mwsqlctl wizard      # from an elevated PowerShell (Run as administrator)");
        } else {
            println!("  mwsqlctl wizard");
        }
    }
    Ok(())
}

/// Non-secret flags to forward across the sudo re-exec. Never `--user` (service
/// mode), never a secret.
fn forwarded_args(opts: &InitOpts) -> Vec<OsString> {
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
    if let Some(ep) = &opts.exec_path {
        v.push("--exec-path".into());
        v.push(ep.as_os_str().to_owned());
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> InitOpts {
        InitOpts {
            state_dir: Some(PathBuf::from("/var/lib/middlewhere")),
            user: false,
            file_keystore: true,
            service_name: "mwsqld".into(),
            exec_path: Some(PathBuf::from("/usr/local/bin/mwsqld")),
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
        assert!(fwd.contains(&"--exec-path".to_string()));
    }

    #[test]
    fn forwarded_args_minimal_when_no_overrides() {
        let o = InitOpts {
            state_dir: None,
            user: false,
            file_keystore: false,
            service_name: "mwsqld".into(),
            exec_path: None,
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
}
