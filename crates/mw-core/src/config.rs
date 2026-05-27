//! Normalized config schema. Bastions, credentials, and envs are independent
//! tables referenced by name. The whole Config is serialized with serde +
//! ciborium and AEAD-sealed by [`crate::seal`]; nothing here is intended to
//! touch disk in cleartext.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::secret::{SecretBytes, SecretStr};

pub const CURRENT_SCHEMA_VERSION: u32 = 2;

/// Backend database engine for an env. Selects the front-side wire protocol,
/// the backend driver, and the firewall dialect. `MySql` is the default so
/// schema-v1 sealed configs (which predate this field) deserialize unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum EngineKind {
    #[default]
    MySql,
    Postgres,
    MsSql,
}

impl EngineKind {
    /// Conventional default backend port for this engine.
    pub fn default_port(self) -> u16 {
        match self {
            EngineKind::MySql => 3306,
            EngineKind::Postgres => 5432,
            EngineKind::MsSql => 1433,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub schema_version: u32,
    pub bastions: BTreeMap<String, Bastion>,
    pub credentials: BTreeMap<String, Credential>,
    pub envs: BTreeMap<String, Env>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            bastions: BTreeMap::new(),
            credentials: BTreeMap::new(),
            envs: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bastion {
    pub host: String,
    pub port: u16,
    pub ssh_user: String,
    pub auth: BastionAuth,
    pub pinned_host_keys: Vec<HostKeyFingerprint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BastionAuth {
    Password {
        password: SecretStr,
    },
    Key {
        private_key_pem: SecretBytes,
        passphrase: Option<SecretStr>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostKeyFingerprint {
    pub algo: String,
    pub sha256_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub backend_user: String,
    pub backend_password: SecretStr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Env {
    pub backend_host: String,
    pub backend_port: u16,
    pub default_database: Option<String>,
    pub bastion: Option<String>,
    pub credential: String,
    pub policy: Policy,
    pub client_auth: ClientAuth,
    pub listen_port: u16,
    pub pool: PoolSettings,
    #[serde(default)]
    pub engine: EngineKind,
}

/// How a client authenticates to the proxy on this env's listener. The proxy
/// stores whatever material the chosen auth plugin needs to verify a client
/// response server-side — never the token itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClientAuth {
    /// `mysql_native_password`: stores SHA1(SHA1(token)).
    NativePassword {
        #[serde(with = "serde_arr20")]
        double_sha1: [u8; 20],
    },
    /// Postgres cleartext-password-over-loopback: stores SHA-256(token). The
    /// proxy requests `AuthenticationCleartextPassword`, then verifies the
    /// `PasswordMessage` against this hash without ever holding the token.
    PgCleartext {
        #[serde(with = "serde_arr32")]
        sha256: [u8; 32],
    },
}

mod serde_arr20 {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 20], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 20], D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = [u8; 20];
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("20 raw bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<[u8; 20], E> {
                v.try_into().map_err(|_| E::invalid_length(v.len(), &self))
            }
            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<[u8; 20], E> {
                self.visit_bytes(&v)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<[u8; 20], A::Error> {
                let mut out = [0u8; 20];
                for slot in out.iter_mut() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(20, &self))?;
                }
                Ok(out)
            }
        }
        d.deserialize_byte_buf(V)
    }
}

mod serde_arr32 {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = [u8; 32];
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("32 raw bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<[u8; 32], E> {
                v.try_into().map_err(|_| E::invalid_length(v.len(), &self))
            }
            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<[u8; 32], E> {
                self.visit_bytes(&v)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<[u8; 32], A::Error> {
                let mut out = [0u8; 32];
                for slot in out.iter_mut() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(32, &self))?;
                }
                Ok(out)
            }
        }
        d.deserialize_byte_buf(V)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[derive(Default)]
pub enum Policy {
    #[default]
    ReadOnly,
    ReadWrite,
    Custom {
        allow_dml: bool,
        allow_ddl: bool,
        allow_admin: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolSettings {
    pub min_idle: u32,
    pub max_size: u32,
    pub idle_timeout_secs: u32,
}

impl Default for PoolSettings {
    fn default() -> Self {
        Self {
            min_idle: 0,
            max_size: 16,
            idle_timeout_secs: 300,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("unknown bastion ref {0:?}")]
    UnknownBastion(String),
    #[error("unknown credential ref {0:?}")]
    UnknownCredential(String),
    #[error("duplicate listen port {0} (envs {1:?} and {2:?})")]
    DuplicateListenPort(u16, String, String),
    #[error("schema version {0} not supported (this build expects {expected})", expected = CURRENT_SCHEMA_VERSION)]
    UnsupportedSchema(u32),
    #[error("env {0:?}: client_auth kind does not match engine {1:?}")]
    EngineAuthMismatch(String, EngineKind),
    #[error("config migration failed: {0}")]
    Migrate(String),
}

impl Config {
    /// Verify every env's bastion/credential ref resolves, every listen port is
    /// unique, and the schema version matches. Does NOT verify network
    /// reachability.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != CURRENT_SCHEMA_VERSION {
            return Err(ConfigError::UnsupportedSchema(self.schema_version));
        }
        let mut seen_ports: BTreeMap<u16, &str> = BTreeMap::new();
        for (env_name, env) in &self.envs {
            if let Some(b) = &env.bastion {
                if !self.bastions.contains_key(b) {
                    return Err(ConfigError::UnknownBastion(b.clone()));
                }
            }
            if !self.credentials.contains_key(&env.credential) {
                return Err(ConfigError::UnknownCredential(env.credential.clone()));
            }
            let auth_ok = match (env.engine, &env.client_auth) {
                (EngineKind::MySql, ClientAuth::NativePassword { .. }) => true,
                (EngineKind::Postgres, ClientAuth::PgCleartext { .. }) => true,
                // MsSql is a stub: the daemon refuses it at bind, so any
                // placeholder auth is tolerated here rather than blocking
                // config creation.
                (EngineKind::MsSql, _) => true,
                _ => false,
            };
            if !auth_ok {
                return Err(ConfigError::EngineAuthMismatch(
                    env_name.clone(),
                    env.engine,
                ));
            }
            if let Some(prev) = seen_ports.insert(env.listen_port, env_name.as_str()) {
                return Err(ConfigError::DuplicateListenPort(
                    env.listen_port,
                    prev.to_string(),
                    env_name.clone(),
                ));
            }
        }
        Ok(())
    }
}

fn schema_version_of(v: &ciborium::Value) -> Option<u32> {
    let map = v.as_map()?;
    for (k, val) in map {
        if k.as_text() == Some("schema_version") {
            let n: i128 = val.as_integer()?.into();
            return u32::try_from(n).ok();
        }
    }
    None
}

fn set_schema_version(v: &mut ciborium::Value, ver: u32) {
    if let ciborium::Value::Map(map) = v {
        for (k, val) in map.iter_mut() {
            if k.as_text() == Some("schema_version") {
                *val = ciborium::Value::Integer(ver.into());
                return;
            }
        }
        map.push((
            ciborium::Value::Text("schema_version".into()),
            ciborium::Value::Integer(ver.into()),
        ));
    }
}

/// Decrypted-plaintext migration. Older sealed configs (schema v1) predate the
/// per-env `engine` field; the field materializes via `#[serde(default)]` on
/// the typed deserialize below, so the only structural change is bumping
/// `schema_version` so [`Config::validate`]'s equality gate passes. Newer
/// schemas than this build are rejected.
pub fn migrate(mut v: ciborium::Value) -> Result<Config, ConfigError> {
    let sv = schema_version_of(&v).unwrap_or(1);
    match sv {
        1 => set_schema_version(&mut v, CURRENT_SCHEMA_VERSION),
        n if n == CURRENT_SCHEMA_VERSION => {}
        other => return Err(ConfigError::UnsupportedSchema(other)),
    }
    v.deserialized::<Config>()
        .map_err(|e| ConfigError::Migrate(e.to_string()))
}

#[cfg(test)]
mod migrate_tests {
    use super::*;
    use crate::secret::SecretStr;

    fn one_env_config() -> Config {
        let mut cfg = Config::default();
        cfg.credentials.insert(
            "c".into(),
            Credential {
                backend_user: "u".into(),
                backend_password: SecretStr::new("pw"),
            },
        );
        cfg.envs.insert(
            "e".into(),
            Env {
                backend_host: "h".into(),
                backend_port: 3306,
                default_database: None,
                bastion: None,
                credential: "c".into(),
                policy: Policy::ReadOnly,
                client_auth: ClientAuth::NativePassword {
                    double_sha1: [0; 20],
                },
                listen_port: 6033,
                pool: PoolSettings::default(),
                engine: EngineKind::MySql,
            },
        );
        cfg
    }

    /// R6: a schema-v1 plaintext (no `engine` key on any env, schema_version=1)
    /// must migrate to v2 with every env defaulting to `MySql` via
    /// `#[serde(default)]`. Falsifies the ciborium-honors-serde-default risk.
    #[test]
    fn v1_blob_without_engine_migrates_to_mysql() {
        let cfg = one_env_config();
        let mut v = ciborium::Value::serialized(&cfg).unwrap();

        // Simulate a genuine v1 blob: strip the `engine` key from every env
        // and stamp schema_version back to 1.
        if let ciborium::Value::Map(top) = &mut v {
            for (k, val) in top.iter_mut() {
                if k.as_text() == Some("envs") {
                    if let ciborium::Value::Map(envs) = val {
                        for (_, envv) in envs.iter_mut() {
                            if let ciborium::Value::Map(em) = envv {
                                em.retain(|(ek, _)| ek.as_text() != Some("engine"));
                            }
                        }
                    }
                }
            }
        }
        set_schema_version(&mut v, 1);
        assert_eq!(schema_version_of(&v), Some(1));

        let migrated = migrate(v).expect("v1 migrates");
        assert_eq!(migrated.schema_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(migrated.envs["e"].engine, EngineKind::MySql);
        migrated.validate().expect("migrated config validates");
    }

    #[test]
    fn v2_blob_roundtrips_unchanged() {
        let cfg = one_env_config();
        let v = ciborium::Value::serialized(&cfg).unwrap();
        let back = migrate(v).expect("v2 passes through");
        assert_eq!(back.schema_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(back.envs["e"].engine, EngineKind::MySql);
    }

    #[test]
    fn future_schema_rejected() {
        let cfg = one_env_config();
        let mut v = ciborium::Value::serialized(&cfg).unwrap();
        set_schema_version(&mut v, 999);
        assert!(matches!(
            migrate(v),
            Err(ConfigError::UnsupportedSchema(999))
        ));
    }
}
