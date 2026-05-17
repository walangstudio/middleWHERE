//! Import a legacy `.env` + `secrets/` deployment into a sealed config.
//! Resolution rules from the env keys:
//!
//! - bastions   = `BASTION_<N>_HOST`
//! - envs       = `<P>_HOST` not starting with `BASTION_`, sorted unique;
//!                listen port = 6033 + index in that sorted order
//! - credential = inline `<P>_USER` (pw `secrets/<p_lc>_password`)
//!                OR `<P>_CREDENTIALS=<K>` → `<K>_USER` (pw `secrets/<k_lc>_password`)
//! - bastion ref = explicit `<P>_BASTION` (`direct`/`none` → none) else the
//!                 longest `BASTION_<N>` that prefixes `<P>_`
//! - port default 3306; pool max from `<P>_MAX_CONNECTIONS` /
//!   `<K>_MAX_CONNECTIONS`
//!
//! Each imported env gets a freshly generated client token (the source had
//! none — clients used the backend user directly). Tokens are NOT printed;
//! the operator runs `mwsqlctl grant <env>` per env afterwards.
//!
//! known_hosts lines become pinned fingerprints computed exactly as
//! `mw_net::ssh::ClientHandler` does: base64_nopad(sha256(wire_key)),
//! so an imported pin actually matches at runtime.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use sha2::{Digest, Sha256};

use mw_core::config::{
    Bastion, BastionAuth, ClientAuth, Config, Credential, EngineKind, Env, HostKeyFingerprint,
    PoolSettings, Policy,
};
use mw_core::secret::{SecretBytes, SecretStr};
use mw_core::state::{load_config, save_config, KeystoreChoice};
use mw_core::token::{double_sha1, generate_token};

const CLIENT_PORT_BASE: u16 = 6033;

#[derive(Debug, Default)]
pub struct ImportReport {
    pub bastions: Vec<String>,
    pub credentials: Vec<String>,
    pub envs: Vec<(String, u16)>, // (name, listen_port)
    pub warnings: Vec<String>,
}

/// Parse a dotenv-ish file: `KEY=VALUE`, optional `export `, `#` comments,
/// blank lines, surrounding single/double quotes stripped.
fn parse_env(text: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((k, v)) = line.split_once('=') else { continue };
        let k = k.trim();
        if k.is_empty() { continue; }
        let mut v = v.trim();
        if v.len() >= 2
            && ((v.starts_with('"') && v.ends_with('"'))
             || (v.starts_with('\'') && v.ends_with('\''))) {
            v = &v[1..v.len() - 1];
        }
        m.insert(k.to_string(), v.to_string());
    }
    m
}

fn read_secret_file(secrets: &Path, name: &str) -> Result<String> {
    // `name` is derived from untrusted .env keys. A hostile source with e.g.
    // `../../../etc/shadow_HOST=x` would otherwise make us read outside
    // `secrets/` and seal the contents as a "password". Reject any name
    // that is absolute or contains a separator / parent component.
    if name.is_empty()
        || name.contains('/') || name.contains('\\')
        || name.split(['/', '\\']).any(|c| c == "..")
        || Path::new(name).is_absolute()
    {
        bail!("refusing secret name {name:?}: must be a plain filename");
    }
    let p = secrets.join(name);
    let s = std::fs::read_to_string(&p)
        .with_context(|| format!("read secret {}", p.display()))?;
    Ok(s.trim_end_matches(['\n', '\r']).to_string())
}

/// Compute the pinned-fingerprint list from an OpenSSH known_hosts file.
/// Each line: `host[,host...] keytype base64blob [comment]`.
fn fingerprints_from_known_hosts(text: &str) -> (Vec<HostKeyFingerprint>, Vec<String>) {
    let mut out = Vec::new();
    let mut warns = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        let mut it = line.split_whitespace();
        let (_hosts, algo, blob) = match (it.next(), it.next(), it.next()) {
            (Some(h), Some(a), Some(b)) => (h, a, b),
            _ => { warns.push(format!("known_hosts line {} malformed; skipped", i + 1)); continue; }
        };
        let wire = match base64::engine::general_purpose::STANDARD.decode(blob) {
            Ok(w) => w,
            Err(_) => { warns.push(format!("known_hosts line {} bad base64; skipped", i + 1)); continue; }
        };
        let digest = Sha256::digest(&wire);
        let sha256_b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest);
        out.push(HostKeyFingerprint { algo: algo.to_string(), sha256_b64 });
    }
    (out, warns)
}

/// Build a Config fragment from a source directory. Does not touch disk
/// beyond reading `<dir>/.env` and `<dir>/secrets/`.
pub fn build_from_dir(src_dir: &Path) -> Result<(Config, ImportReport)> {
    let env_path = src_dir.join(".env");
    let secrets = src_dir.join("secrets");
    let text = std::fs::read_to_string(&env_path)
        .with_context(|| format!("read {}", env_path.display()))?;
    let vars = parse_env(&text);

    let mut report = ImportReport::default();
    let mut cfg = Config::default();

    // --- bastions ---
    let mut bastion_names_up: Vec<String> = vars.keys()
        .filter_map(|k| k.strip_prefix("BASTION_").and_then(|r| r.strip_suffix("_HOST")))
        .map(|s| s.to_string())
        .collect();
    bastion_names_up.sort();
    bastion_names_up.dedup();

    for up in &bastion_names_up {
        let lc = up.to_lowercase();
        let host = vars.get(&format!("BASTION_{up}_HOST"))
            .ok_or_else(|| anyhow!("BASTION_{up}_HOST missing"))?.clone();
        let port: u16 = vars.get(&format!("BASTION_{up}_PORT"))
            .map(|s| s.parse()).transpose().ok().flatten().unwrap_or(22);
        let ssh_user = vars.get(&format!("BASTION_{up}_USER"))
            .cloned().unwrap_or_default();
        let auth_kind = vars.get(&format!("BASTION_{up}_SSH_AUTH"))
            .map(|s| s.as_str()).unwrap_or("password");

        let auth = if auth_kind == "key" {
            let pem = std::fs::read(secrets.join(format!("bastion_{lc}_key")))
                .with_context(|| format!("read bastion_{lc}_key"))?;
            BastionAuth::Key { private_key_pem: SecretBytes::new(pem), passphrase: None }
        } else {
            let pw = read_secret_file(&secrets, &format!("bastion_{lc}_password"))?;
            BastionAuth::Password { password: SecretStr::new(pw) }
        };

        let pinned = match std::fs::read_to_string(secrets.join(format!("bastion_{lc}_known_hosts"))) {
            Ok(kh) => {
                let (fps, warns) = fingerprints_from_known_hosts(&kh);
                report.warnings.extend(warns);
                if fps.is_empty() {
                    report.warnings.push(format!(
                        "bastion {lc}: no usable pinned host keys. The daemon will \
                         REFUSE this bastion until you add a pinned fingerprint, \
                         unless started with --allow-tofu (insecure)."));
                }
                fps
            }
            Err(_) => {
                report.warnings.push(format!(
                    "bastion {lc}: no known_hosts file, host key UNPINNED. The \
                     daemon will REFUSE this bastion until pinned, unless started \
                     with --allow-tofu (insecure)."));
                Vec::new()
            }
        };

        cfg.bastions.insert(lc.clone(), Bastion { host, port, ssh_user, auth, pinned_host_keys: pinned });
        report.bastions.push(lc);
    }

    // --- envs ---
    let mut env_names_up: Vec<String> = vars.keys()
        .filter_map(|k| k.strip_suffix("_HOST").map(|s| s.to_string()))
        .filter(|p| !p.starts_with("BASTION_"))
        // strip_suffix("_HOST") on "BASTION_X_HOST" yields "BASTION_X"
        .filter(|p| vars.contains_key(&format!("{p}_HOST")))
        .collect();
    env_names_up.sort();
    env_names_up.dedup();
    if env_names_up.is_empty() {
        bail!("no envs found in {} (need at least one <NAME>_HOST)", env_path.display());
    }

    for (idx, env_up) in env_names_up.iter().enumerate() {
        let env_lc = env_up.to_lowercase();
        let host = vars.get(&format!("{env_up}_HOST")).unwrap().clone();
        let port: u16 = vars.get(&format!("{env_up}_PORT"))
            .map(|s| s.parse()).transpose().ok().flatten().unwrap_or(3306);

        // credential resolution: inline wins.
        let (cred_name, backend_user, pw_secret) =
            if let Some(u) = vars.get(&format!("{env_up}_USER")) {
                (env_lc.clone(), u.clone(), format!("{env_lc}_password"))
            } else {
                let key = vars.get(&format!("{env_up}_CREDENTIALS"))
                    .ok_or_else(|| anyhow!("env {env_lc}: no inline {env_up}_USER and no {env_up}_CREDENTIALS"))?;
                let key_up = key.to_uppercase();
                let key_lc = key.to_lowercase();
                let u = vars.get(&format!("{key_up}_USER"))
                    .ok_or_else(|| anyhow!("env {env_lc}: {env_up}_CREDENTIALS={key} but {key_up}_USER unset"))?;
                (key_lc.clone(), u.clone(), format!("{key_lc}_password"))
            };

        if !cfg.credentials.contains_key(&cred_name) {
            let pw = read_secret_file(&secrets, &pw_secret)?;
            cfg.credentials.insert(cred_name.clone(), Credential {
                backend_user, backend_password: SecretStr::new(pw),
            });
            report.credentials.push(cred_name.clone());
        }

        // bastion: explicit, else longest-prefix auto-match.
        let bastion = match vars.get(&format!("{env_up}_BASTION")).map(|s| s.as_str()) {
            Some("direct") | Some("none") => None,
            Some(explicit) => {
                let lc = explicit.to_lowercase();
                if !cfg.bastions.contains_key(&lc) {
                    bail!("env {env_lc}: {env_up}_BASTION={explicit} but no such bastion imported");
                }
                Some(lc)
            }
            None => {
                let mut best: Option<&String> = None;
                for up in &bastion_names_up {
                    if format!("{env_up}_").starts_with(&format!("{up}_"))
                        && best.map_or(true, |b| up.len() > b.len()) {
                        best = Some(up);
                    }
                }
                best.map(|b| b.to_lowercase())
            }
        };

        let max_conn = vars.get(&format!("{env_up}_MAX_CONNECTIONS"))
            .or_else(|| {
                vars.get(&format!("{env_up}_CREDENTIALS"))
                    .and_then(|k| vars.get(&format!("{}_MAX_CONNECTIONS", k.to_uppercase())))
            })
            .and_then(|s| s.parse::<u32>().ok());
        let mut pool = PoolSettings::default();
        if let Some(m) = max_conn { pool.max_size = m; }

        let listen_port = CLIENT_PORT_BASE + idx as u16;
        let token = generate_token();
        cfg.envs.insert(env_up.clone(), Env {
            backend_host: host,
            backend_port: port,
            default_database: None,
            bastion,
            credential: cred_name,
            policy: Policy::ReadOnly,
            client_auth: ClientAuth::NativePassword {
                double_sha1: double_sha1(token.expose().as_bytes()),
            },
            listen_port,
            pool,
            engine: EngineKind::MySql,
        });
        report.envs.push((env_up.clone(), listen_port));
    }

    cfg.validate().context("imported config failed validation")?;
    Ok((cfg, report))
}

/// Import into the sealed config at `state_dir`. Refuses if any imported
/// name already exists there.
pub fn import(state_dir: &Path, ks: &KeystoreChoice, src_dir: &Path) -> Result<ImportReport> {
    let (fragment, report) = build_from_dir(src_dir)?;

    let mut existing = load_config(state_dir, ks)?;
    for n in fragment.bastions.keys() {
        if existing.bastions.contains_key(n) { bail!("bastion {n:?} already exists in target config"); }
    }
    for n in fragment.credentials.keys() {
        if existing.credentials.contains_key(n) { bail!("credential {n:?} already exists in target config"); }
    }
    for n in fragment.envs.keys() {
        if existing.envs.contains_key(n) { bail!("env {n:?} already exists in target config"); }
    }
    let used: std::collections::HashSet<u16> =
        existing.envs.values().map(|e| e.listen_port).collect();
    for e in fragment.envs.values() {
        if used.contains(&e.listen_port) {
            bail!("listen port {} collides with an existing env; clear the target first", e.listen_port);
        }
    }

    existing.bastions.extend(fragment.bastions);
    existing.credentials.extend(fragment.credentials);
    existing.envs.extend(fragment.envs);
    save_config(state_dir, ks, &existing)?;
    Ok(report)
}

pub fn decommission_checklist() -> &'static str {
    "\
# Source decommission checklist
1. Verify each env: mwsqlctl env list
2. Mint + distribute client tokens:  mwsqlctl grant <env>   (per env)
3. Smoke test through the daemon before retiring the old source.
4. Shred the old plaintext secrets:  the old secrets/*_password files are
   now superseded — securely delete the entire old secrets/ directory.
5. Pin any UNPINNED bastion host keys (see warnings above).
6. Remove the old .env (it still contains host/topology metadata)."
}
