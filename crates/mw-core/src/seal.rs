//! AEAD-sealed config blob.
//!
//! Format on disk:
//!   magic[8] = "SQLPSEAL"
//!   version[1] = 1
//!   kdf_salt[16]
//!   nonce[12]
//!   ciphertext+tag[..]
//!
//! Plaintext = ciborium-serialized [`crate::config::Config`].
//! Key       = Argon2id(master_key || passphrase, salt = kdf_salt).
//!
//! `master_key` is 32 random bytes from the OS keystore (see
//! [`crate::keyring`]). `passphrase` is optional second-factor entered by an
//! operator; empty string when absent.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;
use rand_core::OsRng;
use zeroize::Zeroize;

use crate::config::Config;
use crate::secret::SecretStr;

const MAGIC: &[u8; 8] = b"SQLPSEAL";
/// Schema-v1 sealed blobs. Still readable: crypto params are identical to V2,
/// only the plaintext schema evolved (handled by [`crate::config::migrate`]).
const V1: u8 = 1;
/// What new seals write.
const VERSION: u8 = 2;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
// AEAD associated data. Stable across schema versions on purpose: crypto
// parameters did not change v1->v2, so binding the schema version in here
// would gratuitously break every sealed file for zero security gain. The
// `.v1` suffix is an AAD generation marker, not the plaintext schema
// version.
const AAD: &[u8] = b"middlewhere.seal.v1";

#[derive(Debug, thiserror::Error)]
pub enum SealError {
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed (wrong master key, wrong passphrase, or tampered file)")]
    Decrypt,
    #[error("malformed sealed blob: {0}")]
    Format(&'static str),
    #[error("argon2 error: {0}")]
    Kdf(argon2::Error),
    #[error("cbor encode: {0}")]
    CborEncode(#[from] ciborium::ser::Error<std::io::Error>),
    #[error("cbor decode: {0}")]
    CborDecode(#[from] ciborium::de::Error<std::io::Error>),
    #[error("migration: {0}")]
    Migrate(#[from] crate::config::ConfigError),
}

/// 32-byte master key. Held in OS keystore in production. Wrapped to forbid
/// accidental logging and to zeroize on drop.
pub struct MasterKey([u8; KEY_LEN]);

impl MasterKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self { Self(bytes) }
    pub fn generate() -> Self {
        let mut k = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut k);
        Self(k)
    }
    pub fn expose(&self) -> &[u8; KEY_LEN] { &self.0 }
}

impl Drop for MasterKey {
    fn drop(&mut self) { self.0.zeroize(); }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey(<redacted>)")
    }
}

/// Optional passphrase. Empty when unused.
#[derive(Default)]
pub struct Passphrase(pub SecretStr);

fn derive_key(
    master: &MasterKey,
    passphrase: &Passphrase,
    salt: &[u8; SALT_LEN],
) -> Result<[u8; KEY_LEN], SealError> {
    use argon2::{Algorithm, Argon2, Params, Version};
    // m=64MiB, t=3, p=4. Parallelism 4 raises an offline attacker's cost on
    // multi-core hardware; the value is not security-load-bearing here (the
    // KDF input is a 256-bit random master key, not a human passphrase) but
    // it is cheap defense in depth.
    let params = Params::new(64 * 1024, 3, 4, Some(KEY_LEN)).map_err(SealError::Kdf)?;
    let kdf = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut ikm = Vec::with_capacity(KEY_LEN + passphrase.0.expose().len());
    ikm.extend_from_slice(master.expose());
    ikm.extend_from_slice(passphrase.0.expose().as_bytes());

    let mut out = [0u8; KEY_LEN];
    let res = kdf.hash_password_into(&ikm, salt, &mut out);
    ikm.zeroize();
    res.map_err(SealError::Kdf)?;
    Ok(out)
}

pub fn seal(cfg: &Config, master: &MasterKey, passphrase: &Passphrase) -> Result<Vec<u8>, SealError> {
    let mut plaintext = Vec::new();
    ciborium::ser::into_writer(cfg, &mut plaintext)?;

    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let mut derived = derive_key(master, passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&derived));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, Payload { msg: &plaintext, aad: AAD })
        .map_err(|_| SealError::Encrypt)?;

    derived.zeroize();
    plaintext.zeroize();

    let mut out = Vec::with_capacity(MAGIC.len() + 1 + SALT_LEN + NONCE_LEN + ct.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn unseal(blob: &[u8], master: &MasterKey, passphrase: &Passphrase) -> Result<Config, SealError> {
    const HEADER: usize = 8 + 1 + SALT_LEN + NONCE_LEN;
    if blob.len() < HEADER + 16 {
        return Err(SealError::Format("blob too short"));
    }
    if &blob[0..8] != MAGIC {
        return Err(SealError::Format("bad magic"));
    }
    if blob[8] != V1 && blob[8] != VERSION {
        return Err(SealError::Format("unknown version"));
    }
    let salt: [u8; SALT_LEN] = blob[9..9 + SALT_LEN].try_into().unwrap();
    let nonce_bytes: [u8; NONCE_LEN] = blob[9 + SALT_LEN..HEADER].try_into().unwrap();
    let ct = &blob[HEADER..];

    let mut derived = derive_key(master, passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&derived));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut plaintext = cipher
        .decrypt(nonce, Payload { msg: ct, aad: AAD })
        .map_err(|_| SealError::Decrypt)?;
    derived.zeroize();

    let value: ciborium::Value = ciborium::de::from_reader(plaintext.as_slice())?;
    plaintext.zeroize();
    let cfg = crate::config::migrate(value)?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_empty() {
        let cfg = Config::default();
        let mk = MasterKey::generate();
        let pp = Passphrase::default();
        let sealed = seal(&cfg, &mk, &pp).unwrap();
        let back = unseal(&sealed, &mk, &pp).unwrap();
        assert_eq!(cfg.schema_version, back.schema_version);
    }

    #[test]
    fn wrong_master_fails() {
        let cfg = Config::default();
        let mk1 = MasterKey::generate();
        let mk2 = MasterKey::generate();
        let pp = Passphrase::default();
        let sealed = seal(&cfg, &mk1, &pp).unwrap();
        assert!(matches!(unseal(&sealed, &mk2, &pp), Err(SealError::Decrypt)));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let cfg = Config::default();
        let mk = MasterKey::generate();
        let pp = Passphrase::default();
        let mut sealed = seal(&cfg, &mk, &pp).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(matches!(unseal(&sealed, &mk, &pp), Err(SealError::Decrypt)));
    }
}
