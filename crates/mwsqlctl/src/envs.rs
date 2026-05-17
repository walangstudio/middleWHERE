//! Env CRUD + token lifecycle.
//!
//! `add` generates a fresh client token and returns it once. The token's
//! double-SHA1 lives in the sealed config; the cleartext token never goes
//! to disk on the daemon side. The operator is responsible for delivering
//! the token to whichever OS user(s) need to connect (Phase 9's
//! `mwsql grant` will automate the client-side keyring write).

use std::path::Path;

use anyhow::{anyhow, bail, Result};

use mw_core::config::{ClientAuth, EngineKind, Env, PoolSettings, Policy};
use mw_core::secret::SecretStr;
use mw_core::state::KeystoreChoice;
use mw_core::token::{double_sha1, generate_token, sha256};

/// Verification material the proxy stores for an env, derived from the token
/// according to the engine's front-side auth scheme.
fn client_auth_for(engine: EngineKind, token: &str) -> ClientAuth {
    match engine {
        EngineKind::Postgres => ClientAuth::PgCleartext { sha256: sha256(token.as_bytes()) },
        // MsSql is a daemon-side stub; store native_password as a placeholder
        // so config round-trips. It is never used (bind refuses MsSql).
        EngineKind::MySql | EngineKind::MsSql =>
            ClientAuth::NativePassword { double_sha1: double_sha1(token.as_bytes()) },
    }
}

use crate::store::with_config;

pub struct EnvAddArgs<'a> {
    pub name: &'a str,
    pub backend_host: &'a str,
    pub backend_port: u16,
    pub default_database: Option<&'a str>,
    pub bastion: Option<&'a str>,
    pub credential: &'a str,
    pub policy: Policy,
    pub listen_port: Option<u16>,
    pub max_pool: Option<u32>,
    pub engine: EngineKind,
}

#[derive(Debug)]
pub struct NewEnvOutput {
    pub token: SecretStr,
    pub listen_port: u16,
}

pub fn add(state_dir: &Path, ks: &KeystoreChoice, args: EnvAddArgs<'_>) -> Result<NewEnvOutput> {
    if args.engine == EngineKind::MsSql {
        bail!("engine 'mssql' is not implemented yet (TDS protocol stub); \
               supported engines: mysql, postgres");
    }
    let token = generate_token();
    let token_for_return = SecretStr::new(token.expose());
    with_config(state_dir, ks, |cfg| {
        if cfg.envs.contains_key(args.name) {
            bail!("env {:?} already exists", args.name);
        }
        if !cfg.credentials.contains_key(args.credential) {
            bail!("credential {:?} not found", args.credential);
        }
        if let Some(b) = args.bastion {
            if !cfg.bastions.contains_key(b) {
                bail!("bastion {:?} not found", b);
            }
        }
        let listen_port = match args.listen_port {
            Some(p) => {
                if cfg.envs.values().any(|e| e.listen_port == p) {
                    bail!("port {p} is already in use by another env");
                }
                p
            }
            None => pick_free_port(cfg).ok_or_else(|| anyhow!("no free listen port in 6033..=6064"))?,
        };
        let mut pool = PoolSettings::default();
        if let Some(n) = args.max_pool { pool.max_size = n; }

        cfg.envs.insert(args.name.to_string(), Env {
            backend_host: args.backend_host.to_string(),
            backend_port: args.backend_port,
            default_database: args.default_database.map(|s| s.to_string()),
            bastion: args.bastion.map(|s| s.to_string()),
            credential: args.credential.to_string(),
            policy: args.policy,
            client_auth: client_auth_for(args.engine, token.expose()),
            listen_port,
            pool,
            engine: args.engine,
        });
        Ok(NewEnvOutput { token: token_for_return, listen_port })
    })
}

pub fn rm(state_dir: &Path, ks: &KeystoreChoice, name: &str) -> Result<()> {
    with_config(state_dir, ks, |cfg| {
        if cfg.envs.remove(name).is_none() {
            bail!("env {:?} not found", name);
        }
        Ok(())
    })
}

pub fn rotate_token(state_dir: &Path, ks: &KeystoreChoice, name: &str) -> Result<SecretStr> {
    Ok(grant(state_dir, ks, name)?.token)
}

/// Rotate the env token and return it together with the env's listen port,
/// so the operator can hand a client identity everything `mwsql login`
/// needs. Rotation invalidates the previous token — one env, one live token,
/// delivered to one place.
pub fn grant(state_dir: &Path, ks: &KeystoreChoice, name: &str) -> Result<NewEnvOutput> {
    let token = generate_token();
    let token_for_return = SecretStr::new(token.expose());
    with_config(state_dir, ks, |cfg| {
        let env = cfg.envs.get_mut(name)
            .ok_or_else(|| anyhow!("env {:?} not found", name))?;
        env.client_auth = client_auth_for(env.engine, token.expose());
        Ok(NewEnvOutput { token: token_for_return, listen_port: env.listen_port })
    })
}

#[derive(Debug, Clone)]
pub struct EnvRow {
    pub name: String,
    pub backend: String,
    pub bastion: Option<String>,
    pub credential: String,
    pub policy: &'static str,
    pub listen_port: u16,
    pub engine: &'static str,
}

pub fn list(state_dir: &Path, ks: &KeystoreChoice) -> Result<Vec<EnvRow>> {
    let cfg = mw_core::state::load_config(state_dir, ks)?;
    Ok(cfg.envs.iter().map(|(name, e)| EnvRow {
        name: name.clone(),
        backend: format!("{}:{}", e.backend_host, e.backend_port),
        bastion: e.bastion.clone(),
        credential: e.credential.clone(),
        policy: policy_label(&e.policy),
        listen_port: e.listen_port,
        engine: engine_label(e.engine),
    }).collect())
}

pub fn engine_label(e: EngineKind) -> &'static str {
    match e {
        EngineKind::MySql => "mysql",
        EngineKind::Postgres => "postgres",
        EngineKind::MsSql => "mssql",
    }
}

const CLIENT_PORT_BASE: u16 = 6033;
const CLIENT_PORT_END: u16 = 6064;

fn pick_free_port(cfg: &mw_core::config::Config) -> Option<u16> {
    let used: std::collections::HashSet<u16> = cfg.envs.values().map(|e| e.listen_port).collect();
    (CLIENT_PORT_BASE..=CLIENT_PORT_END).find(|p| !used.contains(p))
}

pub fn policy_label(p: &Policy) -> &'static str {
    match p {
        Policy::ReadOnly  => "read-only",
        Policy::ReadWrite => "read-write",
        Policy::Custom { .. } => "custom",
    }
}
