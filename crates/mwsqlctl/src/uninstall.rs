//! `mwsqlctl uninstall` — tear down a deployment: the inverse of `init`.
//!
//! Service mode (the default) self-elevates, stops + removes the OS service, and
//! deletes the sealed config and master key. `--user` removes the per-user
//! deployment with no elevation and no service. It is destructive and
//! irreversible — every credential, bastion, and env token-hash go with the
//! state dir — so it confirms first unless `--yes` is given. The append-only
//! audit log under `<state_dir>/audit` is preserved by default (compliance /
//! forensics); `--purge-audit` deletes it too.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use mw_core::state::{
    default_state_dir, default_user_state_dir, resolve_cli_target, KeystoreChoice,
};

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
    /// Also delete the append-only audit log. Off by default: uninstall
    /// preserves `<state_dir>/audit`.
    pub purge_audit: bool,
    /// Set on the Windows UAC-relaunched child: don't re-elevate, and pause
    /// before the (new) console closes so the result stays readable.
    pub uac: bool,
}

pub fn run(opts: UninstallOpts) -> Result<()> {
    run_inner(opts)
}

fn run_inner(opts: UninstallOpts) -> Result<()> {
    let service = !opts.user;

    if service {
        service::validate_service_name(&opts.service_name)?;
    }

    let (state_dir, ks) = resolve_cli_target(opts.state_dir.clone(), opts.user, opts.file_keystore);

    // A per-user deployment — `--user`, or a v0.2.x legacy one the flagless resolve
    // adopted (OS keychain, or a file keystore living in the per-user default dir)
    // — has no service and is owned by THIS user. It must be torn down here,
    // without elevation: an admin/LocalSystem child can't reach this user's
    // keychain to delete an OS-keychain master key (it would orphan it), and there
    // is no service to stop. Only a system-dir service deployment elevates.
    let system_service = is_system_service(opts.user, &state_dir, &ks);

    // Destructive + irreversible: confirm BEFORE elevating, while this process
    // still owns the terminal. The elevated child is launched with --yes so it
    // never prompts (its stdout is redirected under UAC and a prompt there would
    // be invisible). With no terminal to confirm on, refuse rather than wipe a
    // deployment unattended.
    let mut confirmed = opts.yes;
    if !confirmed {
        println!("This permanently removes:");
        if system_service {
            println!("  - the {} service", opts.service_name);
        }
        if opts.purge_audit {
            println!(
                "  - {} (sealed config, master key, audit log)",
                state_dir.display()
            );
        } else {
            println!(
                "  - {} (sealed config, master key; audit log preserved)",
                state_dir.display()
            );
        }
        if !std::io::stdin().is_terminal() {
            bail!("refusing to uninstall without confirmation; pass --yes");
        }
        if !confirm("Continue?", false)? {
            println!("Aborted. Nothing was removed.");
            return Ok(());
        }
        confirmed = true;
    }

    // Removing the service and the root/Admin-owned state dir needs elevation.
    // Elevate-first (already confirmed above): `sudo` re-exec on Linux, a UAC
    // relaunch on Windows. The child carries `--yes` so it does not re-prompt.
    if system_service && service::needs_service_elevation(opts.uac) {
        let forward = forwarded_args(&opts, confirmed, &state_dir, &ks);
        let reason = format!(
            "Uninstalling needs root: it stops and removes the {svc} service and \
             deletes {dir} (config, master key{audit}).",
            svc = opts.service_name,
            dir = state_dir.display(),
            audit = if opts.purge_audit {
                ", audit log"
            } else {
                "; audit log preserved"
            },
        );
        return service::elevate_for_service("uninstall", &forward, &reason);
    }

    // Stop the service first so it releases any handle on the state dir.
    if system_service {
        service::uninstall_service(&opts.service_name)?;
    }

    // Remove the state dir BEFORE clearing the keystore: never destroy the master
    // key while the sealed config it protects still exists, so a failed removal
    // stays recoverable. The file backend's key lives inside the dir and goes with
    // it; clearing the keystore afterwards drops the OS-keychain entry (and is a
    // tolerated no-op for the already-gone file key). The keystore delete runs
    // even when no dir was present, so a pre-removed deployment leaves no dangling
    // keychain entry.
    let removed = remove_state_dir(&state_dir, opts.purge_audit)?;
    ks.delete()?;

    match removed {
        Removal::PreservedAudit => {
            println!(
                "Uninstalled. Removed config and master key from {}.",
                state_dir.display()
            );
            println!(
                "Audit log preserved at {}; pass --purge-audit to remove it.",
                state_dir.join("audit").display()
            );
        }
        Removal::Full => println!("Uninstalled. Removed {}.", state_dir.display()),
        Removal::Absent if system_service => println!(
            "Removed the {} service; no config was present at {}.",
            opts.service_name,
            state_dir.display()
        ),
        Removal::Absent => println!("Nothing to remove at {}.", state_dir.display()),
    }
    Ok(())
}

/// Outcome of clearing the state dir, so the caller can report the right thing.
enum Removal {
    /// The dir did not exist — nothing to tear down.
    Absent,
    /// The whole dir was removed (`--purge-audit`, or no audit log to keep).
    Full,
    /// Everything but `<dir>/audit` was removed; the audit log survives.
    PreservedAudit,
}

/// Clear the state dir. With `purge_audit` (or when no audit dir exists) the
/// whole dir goes; otherwise every entry except `<dir>/audit` is removed and the
/// append-only audit log is left in place.
fn remove_state_dir(dir: &Path, purge_audit: bool) -> Result<Removal> {
    if !dir.exists() {
        return Ok(Removal::Absent);
    }
    let audit = dir.join("audit");
    if purge_audit || !audit.exists() {
        std::fs::remove_dir_all(dir).with_context(|| format!("remove {}", dir.display()))?;
        return Ok(Removal::Full);
    }
    for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let path = entry?.path();
        if path == audit {
            continue;
        }
        let r = if path.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        r.with_context(|| format!("remove {}", path.display()))?;
    }
    Ok(Removal::PreservedAudit)
}

/// Whether this uninstall targets a system service deployment — the only kind
/// that has a service to stop and lives in an admin-owned dir that needs
/// elevation. A per-user deployment (`--user`, an OS-keychain target, or a target
/// resolved to the per-user default dir) is removed in-process; elevating would
/// hand the delete to an admin child that can't reach this user's keychain,
/// orphaning the master key.
fn is_system_service(user: bool, state_dir: &Path, ks: &KeystoreChoice) -> bool {
    !user
        && !matches!(ks, KeystoreChoice::Os { .. })
        && is_system_state_dir(state_dir, &default_state_dir(), &default_user_state_dir())
}

/// Pure core of [`is_system_service`]'s dir test, split out so the env-fragile
/// no-HOME case is unit-testable without touching real paths. A file-keystore
/// deployment is per-user only when its dir is a *genuine* per-user dir — one
/// distinct from the system dir. With HOME/XDG unset `default_user_state_dir()`
/// collapses onto the system dir, so a flagless deployment at the system dir is
/// still the system service (elevate + stop the unit), never per-user. A custom
/// `--state-dir` (neither default) is a system deployment too: `init` registered
/// a unit pointing at it, and it is root/Admin-owned. Classifying positively on
/// the system dir this way (not by inequality with the fragile per-user dir)
/// keeps the no-HOME case correct.
fn is_system_state_dir(state_dir: &Path, system_dir: &Path, user_dir: &Path) -> bool {
    !(user_dir != system_dir && state_dir == user_dir)
}

/// Non-secret flags to forward across the sudo / UAC re-exec. Never `--user`
/// (service mode only). Forwards the EXACT target the parent already resolved and
/// confirmed (`--state-dir <resolved>` + the keystore flag matching `ks`) so the
/// elevated child — which runs with different perms/HOME — can't re-resolve to a
/// different deployment (system vs legacy) and delete something the user never
/// saw. Carries `--yes` (confirmed in the parent) so the child never re-prompts.
fn forwarded_args(
    opts: &UninstallOpts,
    yes: bool,
    resolved_state_dir: &Path,
    ks: &KeystoreChoice,
) -> Vec<OsString> {
    let mut v: Vec<OsString> = vec![
        "--state-dir".into(),
        resolved_state_dir.as_os_str().to_owned(),
    ];
    // Match the child's keystore to the parent's resolved one. Only a file
    // keystore forwards --file-keystore; forcing it on an OS-keychain target would
    // make the child delete a nonexistent master.key and orphan the real key.
    if matches!(ks, KeystoreChoice::File { .. }) {
        v.push("--file-keystore".into());
    }
    v.push("--service-name".into());
    v.push(opts.service_name.clone().into());
    if yes {
        v.push("--yes".into());
    }
    if opts.purge_audit {
        v.push("--purge-audit".into());
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
            purge_audit: true,
            uac: false,
        }
    }

    #[test]
    fn per_user_targets_are_never_a_system_service() {
        // R3-F1/F4: an OS-keychain OR per-user-dir deployment is removed in-process
        // (no elevation), so an admin child can't orphan the keychain master key.
        let sys = Path::new("/srv/mw");
        let per_user = default_user_state_dir();
        let os = KeystoreChoice::default_os();
        let file = KeystoreChoice::default_file(sys);
        assert!(
            !is_system_service(false, sys, &os),
            "OS keychain is per-user regardless of dir"
        );
        assert!(
            !is_system_service(false, &per_user, &file),
            "file keystore at the per-user default dir is legacy per-user, not a service"
        );
        assert!(
            !is_system_service(true, sys, &file),
            "--user is always per-user"
        );
        assert!(
            is_system_service(false, sys, &file),
            "flagless + file keystore + non-per-user dir is the system service"
        );
    }

    #[test]
    fn system_dir_classification_survives_no_home_collapse() {
        // R-F0: the core of the fix. Classify by the system dir positively, not
        // by inequality with the env-fragile per-user dir.
        let system = Path::new("/var/lib/middlewhere");
        let user = Path::new("/home/u/.local/state/middlewhere");
        // Genuine per-user dir (HOME resolved, distinct) → per-user, no elevation.
        assert!(
            !is_system_state_dir(user, system, user),
            "a real per-user dir is not a system service"
        );
        // The system default dir → system service.
        assert!(
            is_system_state_dir(system, system, user),
            "the system dir is a system service"
        );
        // A custom --state-dir (neither default) → system service: init installed
        // a unit for it and it is root-owned, so uninstall must elevate + stop it.
        assert!(
            is_system_state_dir(Path::new("/srv/mw"), system, user),
            "a custom state dir is a system service"
        );
        // The ambiguous case: HOME/XDG unset, so default_user_state_dir()
        // collapsed onto the system dir. The system-dir deployment must STILL be
        // a system service — the old `!= default_user_state_dir()` compare
        // misread it as per-user and skipped both elevation and the unit removal.
        assert!(
            is_system_state_dir(system, system, system),
            "no-HOME collapse: the system dir must still be a system service"
        );
    }

    #[test]
    fn forwarded_args_never_include_user_and_carry_service_flags() {
        let resolved = PathBuf::from("/var/lib/middlewhere");
        let ks = KeystoreChoice::default_file(&resolved);
        let fwd: Vec<String> = forwarded_args(&opts(), true, &resolved, &ks)
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
        assert!(fwd.contains(&"--purge-audit".to_string()));
    }

    #[test]
    fn forwarded_args_always_carry_the_resolved_target() {
        // F2: even with no --state-dir override, the parent-resolved target is
        // forwarded verbatim so the elevated child never re-resolves.
        let o = UninstallOpts {
            state_dir: None,
            user: false,
            file_keystore: false,
            service_name: "mwsqld".into(),
            yes: false,
            purge_audit: false,
            uac: false,
        };
        let resolved = PathBuf::from("C:/ProgramData/middlewhere");
        let ks = KeystoreChoice::default_file(&resolved);
        let fwd: Vec<String> = forwarded_args(&o, false, &resolved, &ks)
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            fwd,
            vec![
                "--state-dir".to_string(),
                "C:/ProgramData/middlewhere".to_string(),
                "--file-keystore".to_string(),
                "--service-name".to_string(),
                "mwsqld".to_string(),
            ]
        );
    }

    #[test]
    fn forwarded_args_does_not_force_file_keystore_for_an_os_target() {
        // Defense-in-depth: if the forward path were ever reached for an OS-keychain
        // target, it must not tell the child to use a file keystore (which would
        // orphan the real keychain key).
        let resolved = PathBuf::from("/home/u/.local/state/middlewhere");
        let ks = KeystoreChoice::default_os();
        let fwd: Vec<String> = forwarded_args(&opts(), true, &resolved, &ks)
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert!(
            !fwd.iter().any(|a| a == "--file-keystore"),
            "must not force --file-keystore for an OS-keychain target"
        );
    }

    fn seeded_state(dir: &Path) {
        std::fs::create_dir_all(dir.join("audit")).unwrap();
        std::fs::write(dir.join("audit").join("audit.jsonl.2026-07-09"), b"{}\n").unwrap();
        std::fs::write(dir.join("config.sealed"), b"x").unwrap();
        std::fs::write(dir.join("master.key"), b"k").unwrap();
    }

    #[test]
    fn default_uninstall_preserves_audit_but_removes_secrets() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("state");
        seeded_state(&dir);

        assert!(matches!(
            remove_state_dir(&dir, false).unwrap(),
            Removal::PreservedAudit
        ));
        assert!(
            dir.join("audit").join("audit.jsonl.2026-07-09").exists(),
            "audit log must survive a default uninstall"
        );
        assert!(!dir.join("config.sealed").exists());
        assert!(!dir.join("master.key").exists());
    }

    #[test]
    fn purge_audit_removes_the_whole_state_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("state");
        seeded_state(&dir);

        assert!(matches!(
            remove_state_dir(&dir, true).unwrap(),
            Removal::Full
        ));
        assert!(!dir.exists(), "--purge-audit removes everything");
    }

    #[test]
    fn without_an_audit_dir_default_removes_everything_and_absent_is_a_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("state");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.sealed"), b"x").unwrap();

        // Nothing to preserve → the whole dir goes even without --purge-audit.
        assert!(matches!(
            remove_state_dir(&dir, false).unwrap(),
            Removal::Full
        ));
        assert!(!dir.exists());
        // A second call on the now-absent dir is a no-op.
        assert!(matches!(
            remove_state_dir(&dir, false).unwrap(),
            Removal::Absent
        ));
    }
}
