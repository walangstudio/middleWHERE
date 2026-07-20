//! Pure config transforms shared by the CLI (offline, sync) and the daemon
//! (online, async). Each function takes `&mut Config` plus owned/borrowed args
//! and performs exactly one validated mutation; persistence (load → seal →
//! save) stays in the caller via [`crate::state::with_config`]. Extracted so a
//! single implementation of "add an env", "rotate a token", etc. serves both
//! the unprivileged CLI and the privileged daemon.

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};

use crate::config::{
    Bastion, BastionAuth, ClientAuth, Config, Credential, EngineKind, Env, HostKeyFingerprint,
    Policy, PoolSettings,
};
use crate::secret::{SecretBytes, SecretStr};
use crate::token::{double_sha1, generate_token, sha256};

const CLIENT_PORT_BASE: u16 = 6033;
const CLIENT_PORT_END: u16 = 6064;

// ---------------------------------------------------------------------------
// bastion
// ---------------------------------------------------------------------------

/// The secret half of a bastion's SSH auth, already resolved (password entered
/// or key bytes read). `Serialize`/`Deserialize` so it can ride the control
/// channel unchanged.
#[derive(Debug, Serialize, Deserialize)]
pub enum BastionAuthInput {
    Password(SecretStr),
    Key {
        pem: SecretBytes,
        passphrase: Option<SecretStr>,
    },
}

pub struct BastionAddArgs<'a> {
    pub name: &'a str,
    pub host: &'a str,
    pub port: u16,
    pub ssh_user: &'a str,
    pub auth: BastionAuthInput,
    pub fingerprint: Option<HostKeyFingerprint>,
}

pub fn add_bastion(cfg: &mut Config, args: BastionAddArgs<'_>) -> Result<()> {
    if cfg.bastions.contains_key(args.name) {
        bail!("bastion {:?} already exists", args.name);
    }
    let auth = match args.auth {
        BastionAuthInput::Password(p) => BastionAuth::Password { password: p },
        BastionAuthInput::Key { pem, passphrase } => BastionAuth::Key {
            private_key_pem: pem,
            passphrase,
        },
    };
    cfg.bastions.insert(
        args.name.to_string(),
        Bastion {
            host: args.host.to_string(),
            port: args.port,
            ssh_user: args.ssh_user.to_string(),
            auth,
            pinned_host_keys: args.fingerprint.into_iter().collect(),
        },
    );
    Ok(())
}

/// Replace a bastion's pinned host keys with a single fingerprint. Used to pin
/// an unpinned bastion in place, without re-entering its secret.
pub fn set_fingerprint(
    cfg: &mut Config,
    name: &str,
    fingerprint: HostKeyFingerprint,
) -> Result<()> {
    let b = cfg
        .bastions
        .get_mut(name)
        .ok_or_else(|| anyhow!("bastion {name:?} not found"))?;
    b.pinned_host_keys = vec![fingerprint];
    Ok(())
}

pub fn rm_bastion(cfg: &mut Config, name: &str) -> Result<()> {
    let users: Vec<&str> = cfg
        .envs
        .iter()
        .filter(|(_, e)| e.bastion.as_deref() == Some(name))
        .map(|(n, _)| n.as_str())
        .collect();
    if !users.is_empty() {
        return Err(anyhow!(
            "bastion {:?} is still referenced by env(s): {}",
            name,
            users.join(", ")
        ));
    }
    if cfg.bastions.remove(name).is_none() {
        bail!("bastion {:?} not found", name);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// credential
// ---------------------------------------------------------------------------

pub fn add_cred(
    cfg: &mut Config,
    name: &str,
    backend_user: &str,
    password: SecretStr,
) -> Result<()> {
    if cfg.credentials.contains_key(name) {
        bail!("credential {:?} already exists", name);
    }
    cfg.credentials.insert(
        name.to_string(),
        Credential {
            backend_user: backend_user.to_string(),
            backend_password: password,
        },
    );
    Ok(())
}

pub fn rotate_cred(cfg: &mut Config, name: &str, new_password: SecretStr) -> Result<()> {
    let cred = cfg
        .credentials
        .get_mut(name)
        .ok_or_else(|| anyhow!("credential {:?} not found", name))?;
    cred.backend_password = new_password;
    Ok(())
}

pub fn rm_cred(cfg: &mut Config, name: &str) -> Result<()> {
    let users: Vec<&str> = cfg
        .envs
        .iter()
        .filter(|(_, e)| e.credential == name)
        .map(|(n, _)| n.as_str())
        .collect();
    if !users.is_empty() {
        return Err(anyhow!(
            "credential {:?} is still referenced by env(s): {}",
            name,
            users.join(", ")
        ));
    }
    if cfg.credentials.remove(name).is_none() {
        bail!("credential {:?} not found", name);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// env + token lifecycle
// ---------------------------------------------------------------------------

/// The client token minted by [`add_env`]/[`grant_env`], returned once. The
/// token's hash is what lands in the config; the cleartext never reaches disk.
#[derive(Debug)]
pub struct NewEnvOutput {
    pub token: SecretStr,
    pub listen_port: u16,
    /// Engine + database, so the caller can render an engine-correct,
    /// paste-ready connection URI without re-reading the config.
    pub engine: EngineKind,
    pub database: Option<String>,
}

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

pub fn add_env(cfg: &mut Config, args: EnvAddArgs<'_>) -> Result<NewEnvOutput> {
    if args.engine == EngineKind::MsSql {
        bail!(
            "engine 'mssql' is not implemented yet (TDS protocol stub); \
               supported engines: mysql, postgres"
        );
    }
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
    if let Some(n) = args.max_pool {
        pool.max_size = n;
    }

    let token = generate_token();
    let token_for_return = SecretStr::new(token.expose());
    cfg.envs.insert(
        args.name.to_string(),
        Env {
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
        },
    );
    Ok(NewEnvOutput {
        token: token_for_return,
        listen_port,
        engine: args.engine,
        database: args.default_database.map(|s| s.to_string()),
    })
}

pub fn rm_env(cfg: &mut Config, name: &str) -> Result<()> {
    if cfg.envs.remove(name).is_none() {
        bail!("env {:?} not found", name);
    }
    Ok(())
}

/// Rotate the env token and return it together with the env's listen port, so
/// the caller can hand a client identity everything `mwsql login` needs.
/// Rotation invalidates the previous token — one env, one live token.
pub fn grant_env(cfg: &mut Config, name: &str) -> Result<NewEnvOutput> {
    let token = generate_token();
    let token_for_return = SecretStr::new(token.expose());
    let env = cfg
        .envs
        .get_mut(name)
        .ok_or_else(|| anyhow!("env {:?} not found", name))?;
    env.client_auth = client_auth_for(env.engine, token.expose());
    Ok(NewEnvOutput {
        token: token_for_return,
        listen_port: env.listen_port,
        engine: env.engine,
        database: env.default_database.clone(),
    })
}

/// Verification material the proxy stores for an env, derived from the token
/// according to the engine's front-side auth scheme.
fn client_auth_for(engine: EngineKind, token: &str) -> ClientAuth {
    match engine {
        EngineKind::Postgres => ClientAuth::PgCleartext {
            sha256: sha256(token.as_bytes()),
        },
        // MsSql is a daemon-side stub; store native_password as a placeholder
        // so config round-trips. It is never used (bind refuses MsSql).
        EngineKind::MySql | EngineKind::MsSql => ClientAuth::NativePassword {
            double_sha1: double_sha1(token.as_bytes()),
        },
    }
}

fn pick_free_port(cfg: &Config) -> Option<u16> {
    let used: std::collections::HashSet<u16> = cfg.envs.values().map(|e| e.listen_port).collect();
    (CLIENT_PORT_BASE..=CLIENT_PORT_END).find(|p| !used.contains(p))
}

// ---------------------------------------------------------------------------
// policy
// ---------------------------------------------------------------------------

/// Target posture for [`set_policy`]. The ReadOnly → ReadWrite confirmation
/// gate lives in the caller (the CLI's `--i-know-what-im-doing` flag / the
/// daemon's request check); this transform only rewrites the field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyTarget {
    ReadOnly,
    ReadWrite,
}

pub fn set_policy(cfg: &mut Config, env_name: &str, target: PolicyTarget) -> Result<()> {
    let env = cfg
        .envs
        .get_mut(env_name)
        .ok_or_else(|| anyhow!("env {:?} not found", env_name))?;
    env.policy = match target {
        PolicyTarget::ReadOnly => Policy::ReadOnly,
        PolicyTarget::ReadWrite => Policy::ReadWrite,
    };
    Ok(())
}

// ---------------------------------------------------------------------------
// import merge
// ---------------------------------------------------------------------------

/// Merge a parsed import `fragment` into `existing`. Refuses if any imported
/// name already exists or any listen port collides — the source directory is
/// parsed by the (unprivileged) caller; only this validated merge touches the
/// live config.
pub fn merge_import(existing: &mut Config, fragment: Config) -> Result<()> {
    for n in fragment.bastions.keys() {
        if existing.bastions.contains_key(n) {
            bail!("bastion {n:?} already exists in target config");
        }
    }
    for n in fragment.credentials.keys() {
        if existing.credentials.contains_key(n) {
            bail!("credential {n:?} already exists in target config");
        }
    }
    for n in fragment.envs.keys() {
        if existing.envs.contains_key(n) {
            bail!("env {n:?} already exists in target config");
        }
    }
    let used: std::collections::HashSet<u16> =
        existing.envs.values().map(|e| e.listen_port).collect();
    for e in fragment.envs.values() {
        if used.contains(&e.listen_port) {
            bail!(
                "listen port {} collides with an existing env; clear the target first",
                e.listen_port
            );
        }
    }

    existing.bastions.extend(fragment.bastions);
    existing.credentials.extend(fragment.credentials);
    existing.envs.extend(fragment.envs);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with_cred() -> Config {
        let mut cfg = Config::default();
        cfg.credentials.insert(
            "c".into(),
            Credential {
                backend_user: "u".into(),
                backend_password: SecretStr::new("p"),
            },
        );
        cfg
    }

    fn env_args<'a>(name: &'a str, credential: &'a str) -> EnvAddArgs<'a> {
        EnvAddArgs {
            name,
            backend_host: "h",
            backend_port: 3306,
            default_database: None,
            bastion: None,
            credential,
            policy: Policy::ReadOnly,
            listen_port: None,
            max_pool: None,
            engine: EngineKind::MySql,
        }
    }

    #[test]
    fn add_env_mints_token_and_stores_matching_hash() {
        let mut cfg = cfg_with_cred();
        let out = add_env(&mut cfg, env_args("e", "c")).unwrap();
        assert!(!out.token.expose().is_empty());
        match &cfg.envs["e"].client_auth {
            ClientAuth::NativePassword {
                double_sha1: stored,
            } => {
                assert_eq!(stored, &double_sha1(out.token.expose().as_bytes()));
            }
            other => panic!("expected native password, got {other:?}"),
        }
    }

    #[test]
    fn add_env_picks_distinct_free_ports_in_range() {
        let mut cfg = cfg_with_cred();
        let a = add_env(&mut cfg, env_args("a", "c")).unwrap();
        let b = add_env(&mut cfg, env_args("b", "c")).unwrap();
        assert_ne!(a.listen_port, b.listen_port);
        assert!((6033..=6064).contains(&a.listen_port));
        assert!((6033..=6064).contains(&b.listen_port));
    }

    #[test]
    fn add_env_rejects_duplicate_and_unknown_refs() {
        let mut cfg = cfg_with_cred();
        add_env(&mut cfg, env_args("e", "c")).unwrap();
        assert!(add_env(&mut cfg, env_args("e", "c"))
            .unwrap_err()
            .to_string()
            .contains("already exists"));
        assert!(add_env(&mut cfg, env_args("x", "ghost"))
            .unwrap_err()
            .to_string()
            .contains("credential"));
        let mut a = env_args("y", "c");
        a.bastion = Some("nope");
        assert!(add_env(&mut cfg, a)
            .unwrap_err()
            .to_string()
            .contains("bastion"));
    }

    #[test]
    fn add_env_rejects_explicit_port_collision() {
        let mut cfg = cfg_with_cred();
        let mut a = env_args("a", "c");
        a.listen_port = Some(6040);
        add_env(&mut cfg, a).unwrap();
        let mut b = env_args("b", "c");
        b.listen_port = Some(6040);
        assert!(add_env(&mut cfg, b)
            .unwrap_err()
            .to_string()
            .contains("already in use"));
    }

    #[test]
    fn add_env_refuses_mssql() {
        let mut cfg = cfg_with_cred();
        let mut a = env_args("e", "c");
        a.engine = EngineKind::MsSql;
        assert!(add_env(&mut cfg, a)
            .unwrap_err()
            .to_string()
            .contains("mssql"));
    }

    #[test]
    fn grant_env_rotates_and_invalidates_old_token() {
        let mut cfg = cfg_with_cred();
        let old = add_env(&mut cfg, env_args("e", "c")).unwrap();
        let new = grant_env(&mut cfg, "e").unwrap();
        assert_ne!(new.token.expose(), old.token.expose());
        assert_eq!(new.listen_port, old.listen_port);
        match &cfg.envs["e"].client_auth {
            ClientAuth::NativePassword {
                double_sha1: stored,
            } => {
                assert_eq!(stored, &double_sha1(new.token.expose().as_bytes()));
                assert_ne!(stored, &double_sha1(old.token.expose().as_bytes()));
            }
            other => panic!("expected native password, got {other:?}"),
        }
        assert!(grant_env(&mut cfg, "ghost")
            .unwrap_err()
            .to_string()
            .contains("not found"));
    }

    #[test]
    fn env_add_postgres_stores_pg_cleartext() {
        let mut cfg = cfg_with_cred();
        let mut a = env_args("e", "c");
        a.engine = EngineKind::Postgres;
        let out = add_env(&mut cfg, a).unwrap();
        match &cfg.envs["e"].client_auth {
            ClientAuth::PgCleartext { sha256: stored } => {
                assert_eq!(stored, &sha256(out.token.expose().as_bytes()));
            }
            other => panic!("expected pg cleartext, got {other:?}"),
        }
    }

    #[test]
    fn rm_env_reports_missing() {
        let mut cfg = cfg_with_cred();
        add_env(&mut cfg, env_args("e", "c")).unwrap();
        rm_env(&mut cfg, "e").unwrap();
        assert!(cfg.envs.is_empty());
        assert!(rm_env(&mut cfg, "e")
            .unwrap_err()
            .to_string()
            .contains("not found"));
    }

    #[test]
    fn cred_add_rotate_and_referenced_rm_refusal() {
        let mut cfg = Config::default();
        add_cred(&mut cfg, "c", "u", SecretStr::new("p1")).unwrap();
        assert!(add_cred(&mut cfg, "c", "u", SecretStr::new("p"))
            .unwrap_err()
            .to_string()
            .contains("already exists"));
        rotate_cred(&mut cfg, "c", SecretStr::new("p2")).unwrap();
        assert_eq!(cfg.credentials["c"].backend_password.expose(), "p2");
        assert!(rotate_cred(&mut cfg, "ghost", SecretStr::new("x"))
            .unwrap_err()
            .to_string()
            .contains("not found"));

        add_env(&mut cfg, env_args("e", "c")).unwrap();
        assert!(rm_cred(&mut cfg, "c")
            .unwrap_err()
            .to_string()
            .contains("still referenced"));
        rm_env(&mut cfg, "e").unwrap();
        rm_cred(&mut cfg, "c").unwrap();
        assert!(cfg.credentials.is_empty());
    }

    #[test]
    fn bastion_add_pin_and_referenced_rm_refusal() {
        let mut cfg = cfg_with_cred();
        add_bastion(
            &mut cfg,
            BastionAddArgs {
                name: "b",
                host: "h",
                port: 22,
                ssh_user: "u",
                auth: BastionAuthInput::Password(SecretStr::new("pw")),
                fingerprint: None,
            },
        )
        .unwrap();
        assert!(add_bastion(
            &mut cfg,
            BastionAddArgs {
                name: "b",
                host: "h",
                port: 22,
                ssh_user: "u",
                auth: BastionAuthInput::Password(SecretStr::new("pw")),
                fingerprint: None,
            },
        )
        .unwrap_err()
        .to_string()
        .contains("already exists"));

        set_fingerprint(
            &mut cfg,
            "b",
            HostKeyFingerprint {
                algo: "ssh-ed25519".into(),
                sha256_b64: "AAAA".into(),
            },
        )
        .unwrap();
        assert_eq!(cfg.bastions["b"].pinned_host_keys.len(), 1);

        let mut a = env_args("e", "c");
        a.bastion = Some("b");
        add_env(&mut cfg, a).unwrap();
        assert!(rm_bastion(&mut cfg, "b")
            .unwrap_err()
            .to_string()
            .contains("still referenced"));
    }

    #[test]
    fn set_policy_flips_posture() {
        let mut cfg = cfg_with_cred();
        add_env(&mut cfg, env_args("e", "c")).unwrap();
        set_policy(&mut cfg, "e", PolicyTarget::ReadWrite).unwrap();
        assert!(matches!(cfg.envs["e"].policy, Policy::ReadWrite));
        set_policy(&mut cfg, "e", PolicyTarget::ReadOnly).unwrap();
        assert!(matches!(cfg.envs["e"].policy, Policy::ReadOnly));
        assert!(set_policy(&mut cfg, "ghost", PolicyTarget::ReadOnly)
            .unwrap_err()
            .to_string()
            .contains("not found"));
    }

    #[test]
    fn merge_import_rejects_name_and_port_collisions() {
        let mut existing = cfg_with_cred();
        add_env(&mut existing, {
            let mut a = env_args("e", "c");
            a.listen_port = Some(6033);
            a
        })
        .unwrap();

        // Name collision on env.
        let mut frag = cfg_with_cred();
        add_env(&mut frag, {
            let mut a = env_args("e", "c");
            a.listen_port = Some(6050);
            a
        })
        .unwrap();
        // frag shares credential name "c" too — that trips first.
        assert!(merge_import(&mut existing, frag)
            .unwrap_err()
            .to_string()
            .contains("already exists"));

        // Port collision with distinct names.
        let mut frag2 = Config::default();
        add_cred(&mut frag2, "c2", "u", SecretStr::new("p")).unwrap();
        add_env(&mut frag2, {
            let mut a = env_args("e2", "c2");
            a.listen_port = Some(6033);
            a
        })
        .unwrap();
        assert!(merge_import(&mut existing, frag2)
            .unwrap_err()
            .to_string()
            .contains("collides"));
    }

    #[test]
    fn merge_import_extends_on_clean_fragment() {
        let mut existing = cfg_with_cred();
        add_env(&mut existing, {
            let mut a = env_args("e", "c");
            a.listen_port = Some(6033);
            a
        })
        .unwrap();

        let mut frag = Config::default();
        add_cred(&mut frag, "c2", "u", SecretStr::new("p")).unwrap();
        add_env(&mut frag, {
            let mut a = env_args("e2", "c2");
            a.listen_port = Some(6050);
            a
        })
        .unwrap();

        merge_import(&mut existing, frag).unwrap();
        assert!(existing.envs.contains_key("e"));
        assert!(existing.envs.contains_key("e2"));
        assert!(existing.credentials.contains_key("c2"));
        existing.validate().unwrap();
    }
}
