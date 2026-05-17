//! OS-keystore-backed storage for the 32-byte master key.
//!
//! Default backend uses the `keyring` crate, which dispatches to:
//!   - DPAPI / Windows Credential Manager
//!   - macOS Keychain
//!   - Secret Service (libsecret) on Linux
//!
//! For headless Linux (no D-Bus session), [`FileStore`] keeps the key in a
//! mode-0400 file owned by the running user. Callers pick the backend at
//! install time; runtime defaults to [`OsStore`].

use std::path::{Path, PathBuf};

use crate::seal::MasterKey;

const KEY_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum KeyringError {
    #[error("keystore entry not found")]
    NotFound,
    #[error("keystore backend error: {0}")]
    Backend(String),
    #[error("stored key has wrong length (got {0}, want 32)")]
    BadLength(usize),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("hex decode: {0}")]
    Hex(#[from] hex::FromHexError),
}

pub trait MasterKeyStore {
    fn load(&self) -> Result<MasterKey, KeyringError>;
    fn store(&self, key: &MasterKey) -> Result<(), KeyringError>;
    fn delete(&self) -> Result<(), KeyringError>;
}

/// OS-native secret store. `service` and `account` together identify the entry
/// (e.g. "middlewhere" + the service-account username).
pub struct OsStore {
    service: String,
    account: String,
}

impl OsStore {
    pub fn new(service: impl Into<String>, account: impl Into<String>) -> Self {
        Self { service: service.into(), account: account.into() }
    }

    fn entry(&self) -> Result<keyring::Entry, KeyringError> {
        keyring::Entry::new(&self.service, &self.account)
            .map_err(|e| KeyringError::Backend(e.to_string()))
    }
}

impl MasterKeyStore for OsStore {
    fn load(&self) -> Result<MasterKey, KeyringError> {
        let entry = self.entry()?;
        let encoded = entry.get_password().map_err(|e| match e {
            keyring::Error::NoEntry => KeyringError::NotFound,
            other => KeyringError::Backend(other.to_string()),
        })?;
        let raw = hex::decode(encoded.trim())?;
        let arr: [u8; KEY_LEN] = raw
            .as_slice()
            .try_into()
            .map_err(|_| KeyringError::BadLength(raw.len()))?;
        Ok(MasterKey::from_bytes(arr))
    }

    fn store(&self, key: &MasterKey) -> Result<(), KeyringError> {
        let entry = self.entry()?;
        let encoded = hex::encode(key.expose());
        entry
            .set_password(&encoded)
            .map_err(|e| KeyringError::Backend(e.to_string()))
    }

    fn delete(&self) -> Result<(), KeyringError> {
        let entry = self.entry()?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Err(KeyringError::NotFound),
            Err(e) => Err(KeyringError::Backend(e.to_string())),
        }
    }
}

/// Mode-0400 file fallback for headless Linux. Caller must arrange that the
/// containing directory is only readable by the service account.
pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    pub fn new(path: impl AsRef<Path>) -> Self { Self { path: path.as_ref().to_owned() } }
}

impl MasterKeyStore for FileStore {
    fn load(&self) -> Result<MasterKey, KeyringError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => {
                let arr: [u8; KEY_LEN] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| KeyringError::BadLength(bytes.len()))?;
                Ok(MasterKey::from_bytes(arr))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(KeyringError::NotFound),
            Err(e) => Err(KeyringError::Io(e)),
        }
    }

    fn store(&self, key: &MasterKey) -> Result<(), KeyringError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        write_secret_file(&self.path, key.expose())?;
        Ok(())
    }

    fn delete(&self) -> Result<(), KeyringError> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(KeyringError::NotFound),
            Err(e) => Err(KeyringError::Io(e)),
        }
    }
}

#[cfg(unix)]
fn write_secret_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true).create(true).truncate(true).mode(0o400)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

#[cfg(windows)]
fn write_secret_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    // NTFS ACLs are the real defense here; FileStore on Windows is a fallback
    // path mostly for tests. Production Windows installs use OsStore (DPAPI).
    std::fs::write(path, bytes)
}
