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
}

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
