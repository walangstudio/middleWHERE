//! Sealed-config lifecycle: keystore choice, init, load, save.
//!
//! Both `mwsqld` and `mwsqlctl` use this so neither has to know how the
//! other reaches the master key or where the sealed blob lives.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use tracing::info;

use crate::config::Config;
use crate::keyring::{FileStore, MasterKeyStore, OsStore};
use crate::seal::{seal, unseal, MasterKey, Passphrase};

pub const DEFAULT_SERVICE: &str = "middlewhere";
pub const DEFAULT_ACCOUNT: &str = "default";
pub const CONFIG_FILE_NAME: &str = "config.sealed";
pub const CONFIG_BACKUP_NAME: &str = "config.sealed.bak";
pub const CONFIG_TMP_NAME: &str = "config.sealed.tmp";
pub const FILE_MASTER_KEY_NAME: &str = "master.key";

#[derive(Clone, Debug)]
pub enum KeystoreChoice {
    Os { service: String, account: String },
    File { path: PathBuf },
}

impl KeystoreChoice {
    pub fn default_os() -> Self {
        Self::Os {
            service: DEFAULT_SERVICE.into(),
            account: DEFAULT_ACCOUNT.into(),
        }
    }
    pub fn default_file(state_dir: &Path) -> Self {
        Self::File {
            path: state_dir.join(FILE_MASTER_KEY_NAME),
        }
    }
    pub fn load(&self) -> Result<MasterKey> {
        match self {
            KeystoreChoice::Os { service, account } => {
                Ok(OsStore::new(service.clone(), account.clone())
                    .load()
                    .with_context(|| {
                        format!("loading master key from OS keystore ({service}/{account})")
                    })?)
            }
            KeystoreChoice::File { path } => Ok(FileStore::new(path)
                .load()
                .with_context(|| format!("loading master key from {}", path.display()))?),
        }
    }
    pub fn store(&self, key: &MasterKey) -> Result<()> {
        match self {
            KeystoreChoice::Os { service, account } => {
                Ok(OsStore::new(service.clone(), account.clone()).store(key)?)
            }
            KeystoreChoice::File { path } => Ok(FileStore::new(path).store(key)?),
        }
    }
    /// Remove the stored master key. Used by `uninstall`. A key that is already
    /// gone is not an error, so teardown is idempotent. For the file backend this
    /// deletes `master.key`; for the OS backend it removes the keychain entry that
    /// removing the state dir would otherwise leave dangling.
    pub fn delete(&self) -> Result<()> {
        let r = match self {
            KeystoreChoice::Os { service, account } => {
                OsStore::new(service.clone(), account.clone()).delete()
            }
            KeystoreChoice::File { path } => FileStore::new(path).delete(),
        };
        match r {
            Ok(()) | Err(crate::keyring::KeyringError::NotFound) => Ok(()),
            Err(e) => Err(anyhow::Error::new(e).context("delete master key")),
        }
    }
}

/// System-wide state dir for a daemon running as its own service account.
/// This is the **default** for `mwsqld`/`mwsqlctl` (service-first): the common
/// deployment is a managed service, so a flagless invocation targets it and
/// nudges `sudo` on EPERM. `--user` selects [`default_user_state_dir`] instead.
/// Needs elevation to create.
pub fn default_state_dir() -> PathBuf {
    #[cfg(windows)]
    {
        let pd = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        pd.join("middlewhere")
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/middlewhere")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        PathBuf::from("/var/lib/middlewhere")
    }
}

/// Per-user state dir, selected by the `--user` flag so `init`/`run` work with
/// no elevation. Mirrors where the binaries install by default (`~/.local/bin`,
/// `%LOCALAPPDATA%`). The flagless default is the service dir
/// (see [`default_state_dir`]). Falls back to the system dir only if the home
/// directory cannot be resolved.
pub fn default_user_state_dir() -> PathBuf {
    // An env var that is set but empty must be treated as unset (XDG spec), or
    // PathBuf::from("").join(..) yields a relative path and state lands under
    // the CWD.
    fn env_dir(key: &str) -> Option<PathBuf> {
        std::env::var_os(key)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    }
    #[cfg(windows)]
    {
        if let Some(local) = env_dir("LOCALAPPDATA") {
            return local.join("middlewhere");
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = env_dir("HOME") {
            return home.join("Library/Application Support/middlewhere");
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(state) = env_dir("XDG_STATE_HOME") {
            return state.join("middlewhere");
        }
        if let Some(home) = env_dir("HOME") {
            return home.join(".local/state/middlewhere");
        }
    }
    default_state_dir()
}

/// True when an environment variable holds a truthy value (`1`/`true`/`yes`/
/// `on`, case-insensitive). Unset, empty, or a falsey value is false. Used for
/// `MW_FILE_KEYSTORE` / `MW_USER`, where a clap `bool` + `env` would reject a
/// non-`true` string like `1`.
pub fn env_flag(key: &str) -> bool {
    match std::env::var(key) {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

/// Resolve the state dir + keystore from the three flags every CLI shares
/// (`--state-dir`, `--user`, `--file-keystore`). Service-first rules:
///
/// * state dir = explicit `--state-dir`, else the service dir, else the
///   per-user dir when `--user` is set.
/// * keystore  = file when `--file-keystore` or in the (default) service mode —
///   a daemon under a service account has no login session to reach an OS
///   keychain — and the OS keychain only in `--user` mode.
///
/// So the daemon's master key always lands in `master.key` for a service
/// deployment, and an interactive `--user` run gets the OS-integrated store.
pub fn resolve_cli_target(
    state_dir: Option<PathBuf>,
    user: bool,
    file_keystore: bool,
) -> (PathBuf, KeystoreChoice) {
    resolve_target(state_dir, user, file_keystore, true)
}

/// Resolve for **installing a fresh system service** (`init`, service install).
/// Same rules as [`resolve_cli_target`] except it never adopts a v0.2.x per-user
/// deployment: the service runs as its own account (LocalSystem / a service
/// user) and cannot reach the installing user's OS keychain to unseal a
/// per-user config, so adopting it would register a service that fails every
/// start. When a legacy per-user config is present it is left untouched and only
/// noted, and a fresh system config is seeded instead.
pub fn resolve_service_install_target(
    state_dir: Option<PathBuf>,
    user: bool,
    file_keystore: bool,
) -> (PathBuf, KeystoreChoice) {
    resolve_target(state_dir, user, file_keystore, false)
}

fn resolve_target(
    state_dir: Option<PathBuf>,
    user: bool,
    file_keystore: bool,
    allow_legacy_fallback: bool,
) -> (PathBuf, KeystoreChoice) {
    // Upgrade guard for v0.2.x, whose flagless default was the per-user dir. This
    // branch flips the flagless default to the system dir + file keystore, so
    // without this a flagless read/config invocation over an existing per-user
    // install would read an empty system store (envs/creds appear to vanish).
    // When no explicit target is given and only the legacy per-user dir already
    // holds a sealed config, stay on it and point the user at the new default.
    // The install path (`allow_legacy_fallback = false`) must NOT adopt it —
    // see `resolve_service_install_target` — so it only notes the legacy dir and
    // seeds a fresh system config.
    if state_dir.is_none() && !user {
        let system = default_state_dir();
        let legacy = default_user_state_dir();
        if should_use_legacy_user_dir(
            &system,
            system.join(CONFIG_FILE_NAME).exists(),
            &legacy,
            legacy.join(CONFIG_FILE_NAME).exists(),
        ) {
            if allow_legacy_fallback {
                eprintln!(
                    "warning: using legacy per-user state dir {} (the v0.2.x \
                     default); the default is now {}. Pass --user or --state-dir \
                     {} to pin it, or move config.sealed into the system dir to \
                     adopt the new default.",
                    legacy.display(),
                    system.display(),
                    legacy.display(),
                );
                // Pick the keystore the legacy deployment used: `master.key`
                // present means the file store, its absence means the OS keychain
                // that v0.2.x defaulted to.
                let ks = if legacy.join(FILE_MASTER_KEY_NAME).exists() {
                    KeystoreChoice::default_file(&legacy)
                } else {
                    KeystoreChoice::default_os()
                };
                return (legacy, ks);
            }
            eprintln!(
                "note: detected an existing per-user deployment at {}; leaving it \
                 untouched and seeding a fresh system service config at {}. Its \
                 envs/credentials will not carry over — re-add them, or run with \
                 --user to keep using the per-user deployment.",
                legacy.display(),
                system.display(),
            );
        }
    }

    let dir = state_dir.unwrap_or_else(|| {
        if user {
            default_user_state_dir()
        } else {
            default_state_dir()
        }
    });
    let ks = if user && !file_keystore {
        KeystoreChoice::default_os()
    } else {
        KeystoreChoice::default_file(&dir)
    };
    (dir, ks)
}

/// Pure core of the [`resolve_cli_target`] legacy-dir fallback, split out so the
/// decision is unit-testable without touching real system paths (the system dir
/// is unwritable in tests and, on Linux, not even env-overridable). A flagless
/// invocation should stay on the legacy per-user dir only when it, and not the
/// new system dir, already holds a sealed config — and never when the two
/// resolve to the same path (no home dir), which would just warn about itself.
fn should_use_legacy_user_dir(
    system_dir: &Path,
    system_has_config: bool,
    legacy_dir: &Path,
    legacy_has_config: bool,
) -> bool {
    legacy_dir != system_dir && !system_has_config && legacy_has_config
}

/// First-time setup: state dirs, fresh master key in the chosen keystore,
/// sealed empty `Config`. Refuses to overwrite an existing sealed blob.
// Create a directory (and parents) and lock it to the owner. On a
// permission-denied — the common case when the default state dir lives under
// /var/lib and init was run unprivileged — translate the raw OS error into an
// actionable hint instead of a bare "Permission denied".
fn create_dir_secure(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            anyhow!(
                "permission denied creating {}: re-run with sudo, or pass \
                 --state-dir <a path you own> (e.g. ~/.middlewhere)",
                dir.display()
            )
        } else {
            anyhow::Error::new(e).context(format!("create {}", dir.display()))
        }
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("lock {} to 0700", dir.display()))?;
    }
    Ok(())
}

pub fn init(state_dir: &Path, keystore: &KeystoreChoice) -> Result<()> {
    create_dir_secure(state_dir)?;
    create_dir_secure(&state_dir.join("audit"))?;

    let sealed_path = state_dir.join(CONFIG_FILE_NAME);
    if sealed_path.exists() {
        return Err(anyhow!(
            "{} already exists; refusing to overwrite",
            sealed_path.display()
        ));
    }

    let key = MasterKey::generate();
    keystore.store(&key)?;

    let cfg = Config::default();
    let blob = seal(&cfg, &key, &Passphrase::default())?;
    write_atomic(&sealed_path, &blob)?;
    info!(state_dir = %state_dir.display(), "init complete");
    Ok(())
}

pub fn load_config(state_dir: &Path, keystore: &KeystoreChoice) -> Result<Config> {
    let sealed_path = state_dir.join(CONFIG_FILE_NAME);
    let blob =
        std::fs::read(&sealed_path).with_context(|| format!("read {}", sealed_path.display()))?;
    let key = keystore.load()?;
    let cfg = unseal(&blob, &key, &Passphrase::default())?;
    cfg.validate()?;
    Ok(cfg)
}

/// Atomic sealed-config save with one backup level. Sequence:
///   1. seal the new Config in memory
///   2. validate it (refuse to write a broken store)
///   3. rename existing config.sealed -> config.sealed.bak (overwriting prior)
///   4. write config.sealed.tmp, fsync, rename to config.sealed
pub fn save_config(state_dir: &Path, keystore: &KeystoreChoice, cfg: &Config) -> Result<()> {
    cfg.validate()?;
    let key = keystore.load()?;
    let blob = seal(cfg, &key, &Passphrase::default())?;

    let sealed = state_dir.join(CONFIG_FILE_NAME);
    let backup = state_dir.join(CONFIG_BACKUP_NAME);
    if sealed.exists() {
        let _ = std::fs::remove_file(&backup);
        std::fs::rename(&sealed, &backup)
            .with_context(|| format!("rotate {} -> {}", sealed.display(), backup.display()))?;
    }
    write_atomic(&sealed, &blob)?;
    Ok(())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("no parent dir for {}", path.display()))?;
    std::fs::create_dir_all(parent)?;
    let tmp = parent.join(CONFIG_TMP_NAME);
    {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        // The sealed blob is AEAD ciphertext, but defense in depth: never
        // leave it group/world-readable. systemd StateDirectory=0700 covers
        // the standard path; a custom --state-dir would not.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&tmp)
            .with_context(|| format!("open {}", tmp.display()))?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn init_load_save_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let ks = KeystoreChoice::default_file(tmp.path());
        init(tmp.path(), &ks).unwrap();
        let cfg = load_config(tmp.path(), &ks).unwrap();
        assert!(cfg.envs.is_empty());

        // Mutate and save.
        let mut cfg2 = cfg.clone();
        cfg2.credentials.insert(
            "c1".into(),
            crate::config::Credential {
                backend_user: "u".into(),
                backend_password: crate::secret::SecretStr::new("p"),
            },
        );
        save_config(tmp.path(), &ks, &cfg2).unwrap();

        let back = load_config(tmp.path(), &ks).unwrap();
        assert!(back.credentials.contains_key("c1"));

        // Backup file present after first save.
        assert!(tmp.path().join(CONFIG_BACKUP_NAME).exists());
        // Tmp file gone after save.
        assert!(!tmp.path().join(CONFIG_TMP_NAME).exists());
    }

    // Serializes the tests that read or mutate process-global env so they
    // never race; poison-tolerant so one failure doesn't cascade.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn user_state_dir_xdg_resolution() {
        use std::ffi::OsString;
        let _g = env_lock();
        let prev_xdg = std::env::var_os("XDG_STATE_HOME");
        let prev_home = std::env::var_os("HOME");

        // Capture all results while we hold the env, then restore BEFORE
        // asserting so a failed assert can't leak the override.
        std::env::set_var("XDG_STATE_HOME", "/tmp/mw-xdg");
        let with_xdg = default_user_state_dir();
        std::env::set_var("XDG_STATE_HOME", ""); // empty must be ignored
        std::env::set_var("HOME", "/home/tester");
        let empty_xdg = default_user_state_dir();
        std::env::remove_var("XDG_STATE_HOME");
        let no_xdg = default_user_state_dir();

        let restore = |k: &str, v: Option<OsString>| match v {
            Some(v) => std::env::set_var(k, v),
            None => std::env::remove_var(k),
        };
        restore("XDG_STATE_HOME", prev_xdg);
        restore("HOME", prev_home);

        assert_eq!(with_xdg, PathBuf::from("/tmp/mw-xdg/middlewhere"));
        assert_eq!(
            empty_xdg,
            PathBuf::from("/home/tester/.local/state/middlewhere"),
            "empty XDG_STATE_HOME must fall back to HOME, not a relative path"
        );
        assert_eq!(
            no_xdg,
            PathBuf::from("/home/tester/.local/state/middlewhere")
        );
    }

    #[test]
    fn env_flag_truthy_values() {
        let _g = env_lock();
        let prev = std::env::var_os("MW_TEST_FLAG");
        for (v, want) in [
            ("1", true),
            ("true", true),
            ("YES", true),
            ("on", true),
            ("0", false),
            ("false", false),
            ("", false),
        ] {
            std::env::set_var("MW_TEST_FLAG", v);
            assert_eq!(env_flag("MW_TEST_FLAG"), want, "value {v:?}");
        }
        std::env::remove_var("MW_TEST_FLAG");
        assert!(!env_flag("MW_TEST_FLAG"), "unset must be false");
        match prev {
            Some(v) => std::env::set_var("MW_TEST_FLAG", v),
            None => std::env::remove_var("MW_TEST_FLAG"),
        }
    }

    // Point the per-user dir at `dir` for the platform whose env
    // `default_user_state_dir` consults, returning (key, previous) to restore.
    fn set_user_dir_env(dir: &Path) -> (&'static str, Option<std::ffi::OsString>) {
        #[cfg(windows)]
        let key = "LOCALAPPDATA";
        #[cfg(target_os = "macos")]
        let key = "HOME";
        #[cfg(all(unix, not(target_os = "macos")))]
        let key = "XDG_STATE_HOME";
        let prev = std::env::var_os(key);
        std::env::set_var(key, dir);
        (key, prev)
    }

    #[test]
    fn resolve_target_is_service_first() {
        let _g = env_lock();
        // Empty per-user dir so the legacy-deployment fallback (which stats
        // config.sealed there) can't fire on a box that has a real v0.2.x install.
        let tmp = TempDir::new().unwrap();
        let (key, prev) = set_user_dir_env(tmp.path());

        let (dir, ks) = resolve_cli_target(None, false, false);
        let (udir, uks) = resolve_cli_target(None, true, false);
        let (_, fks) = resolve_cli_target(None, true, true);
        let custom = PathBuf::from("/srv/mw");
        let (cdir, _) = resolve_cli_target(Some(custom.clone()), false, false);

        let want_service = default_state_dir();
        let want_user = default_user_state_dir();
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }

        // Flagless: service dir + file keystore.
        assert_eq!(dir, want_service);
        assert!(matches!(ks, KeystoreChoice::File { .. }));
        // --user: per-user dir + OS keychain.
        assert_eq!(udir, want_user);
        assert!(matches!(uks, KeystoreChoice::Os { .. }));
        // --user --file-keystore: per-user dir but file keystore.
        assert!(matches!(fks, KeystoreChoice::File { .. }));
        // Explicit --state-dir wins over the mode default.
        assert_eq!(cdir, custom);
    }

    #[test]
    fn legacy_user_dir_fallback_decision() {
        let sys = Path::new("/system");
        let legacy = Path::new("/legacy");
        // Only the legacy dir has a sealed config: fall back to it.
        assert!(should_use_legacy_user_dir(sys, false, legacy, true));
        // System already seeded (migrated): never fall back.
        assert!(!should_use_legacy_user_dir(sys, true, legacy, true));
        // Fresh install, nothing anywhere.
        assert!(!should_use_legacy_user_dir(sys, false, legacy, false));
        // Only the system dir has config.
        assert!(!should_use_legacy_user_dir(sys, true, legacy, false));
        // No home resolved: dirs coincide, don't warn about self.
        assert!(!should_use_legacy_user_dir(sys, false, sys, true));
    }

    // Drives the real fallback end-to-end. Only Linux lets us keep the system
    // dir empty without root (it is the hardcoded /var/lib/middlewhere, assumed
    // absent in CI) while overriding the per-user dir via XDG_STATE_HOME.
    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn flagless_falls_back_to_legacy_user_deployment() {
        let _g = env_lock();
        let tmp = TempDir::new().unwrap();
        let (key, prev) = set_user_dir_env(tmp.path());
        let legacy = default_user_state_dir();
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(legacy.join(CONFIG_FILE_NAME), b"sealed").unwrap();

        // No master.key -> OS keychain (v0.2.x flagless default).
        let (os_dir, os_ks) = resolve_cli_target(None, false, false);
        // Same inputs, install intent: must NOT adopt the legacy dir.
        let (install_dir, install_ks) = resolve_service_install_target(None, false, false);
        // master.key present -> file store (v0.2.x --file-keystore deployment).
        std::fs::write(legacy.join(FILE_MASTER_KEY_NAME), b"k").unwrap();
        let (file_dir, file_ks) = resolve_cli_target(None, false, false);

        let system = default_state_dir();
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }

        // Read/config path adopts the legacy deployment (finding 4).
        assert_eq!(os_dir, legacy);
        assert!(matches!(os_ks, KeystoreChoice::Os { .. }));
        assert_eq!(file_dir, legacy);
        assert!(matches!(file_ks, KeystoreChoice::File { .. }));
        // Install path seeds a fresh system config instead (finding F3).
        assert_eq!(install_dir, system);
        assert!(matches!(install_ks, KeystoreChoice::File { .. }));
    }

    #[test]
    fn user_state_dir_is_always_absolute() {
        // Whatever the environment, the resolved dir must be absolute — never a
        // CWD-relative path (the empty-env-var regression).
        let _g = env_lock();
        assert!(
            default_user_state_dir().is_absolute(),
            "state dir must be absolute, got {:?}",
            default_user_state_dir()
        );
    }

    #[cfg(unix)]
    #[test]
    fn init_locks_state_and_audit_dirs_to_0700() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let sd = tmp.path().join("state");
        let ks = KeystoreChoice::default_file(&sd);
        init(&sd, &ks).unwrap();
        let mode = std::fs::metadata(&sd).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "state dir must be owner-only");
        let audit_mode = std::fs::metadata(sd.join("audit"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(audit_mode, 0o700, "audit dir must be owner-only");
    }

    #[test]
    fn save_rejects_invalid_config() {
        let tmp = TempDir::new().unwrap();
        let ks = KeystoreChoice::default_file(tmp.path());
        init(tmp.path(), &ks).unwrap();
        let mut cfg = load_config(tmp.path(), &ks).unwrap();
        cfg.envs.insert(
            "dangling".into(),
            crate::config::Env {
                backend_host: "h".into(),
                backend_port: 3306,
                default_database: None,
                bastion: None,
                credential: "missing".into(),
                policy: crate::config::Policy::ReadOnly,
                client_auth: crate::config::ClientAuth::NativePassword {
                    double_sha1: [0; 20],
                },
                listen_port: 6033,
                pool: crate::config::PoolSettings::default(),
                engine: crate::config::EngineKind::MySql,
            },
        );
        assert!(save_config(tmp.path(), &ks, &cfg).is_err());
    }
}
