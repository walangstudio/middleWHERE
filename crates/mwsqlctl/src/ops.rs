//! Shared command logic for the `mwsqlctl` bin and the `wizard`.
//!
//! Each clap subcommand arm and each wizard step funnels through one function
//! here, so secret prompting, argument assembly, and the CRUD call live in a
//! single place. Functions stay quiet — they return data/strings and let the
//! caller print — so they're driveable from tests and from the wizard without
//! duplicating `main`'s glue.

use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};

use mw_core::config::{EngineKind, HostKeyFingerprint, Policy};
use mw_core::secret::{SecretBytes, SecretStr};
use mw_core::state::{init as state_init, KeystoreChoice, CONFIG_FILE_NAME};

use crate::installer::{self, InstallParams};
use crate::{bastion, cred, envs};

/// The (state dir, keystore) pair every op needs. Built once per session.
#[derive(Clone, Copy)]
pub struct Target<'a> {
    pub state_dir: &'a Path,
    pub ks: &'a KeystoreChoice,
}

impl<'a> Target<'a> {
    pub fn new(state_dir: &'a Path, ks: &'a KeystoreChoice) -> Self {
        Self { state_dir, ks }
    }
}

/// True once `init` has sealed a config in this state dir. The signal the
/// wizard uses to decide between first-run and add-more.
pub fn is_initialized(state_dir: &Path) -> bool {
    state_dir.join(CONFIG_FILE_NAME).exists()
}

/// First-time setup. Wraps [`mw_core::state::init`], which creates the dirs and
/// refuses to overwrite an existing sealed config.
pub fn init(t: Target) -> Result<()> {
    state_init(t.state_dir, t.ks)
}

/// Non-secret inputs for adding a bastion; the secret (password or key
/// passphrase) is prompted in-process by [`add_bastion`].
pub struct BastionInput {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub ssh_user: String,
    /// PEM private key path; when set, key auth is used instead of a password.
    pub key_file: Option<PathBuf>,
    /// Read the bastion password from stdin instead of prompting.
    pub password_stdin: bool,
    pub fingerprints: Vec<String>,
}

/// Resolve a bastion's auth secret in-process: read the PEM key file (prompting
/// for a passphrase) or prompt for the SSH password. Shared by the offline
/// [`add_bastion`] and the online control-channel path so both prompt
/// identically before the secret is sealed / sent.
pub fn resolve_bastion_auth(input: &BastionInput) -> Result<bastion::BastionAuthInput> {
    if let Some(path) = &input.key_file {
        let pem = std::fs::read(path).with_context(|| format!("read key {}", path.display()))?;
        let passphrase = if read_yes_no("key has a passphrase? [y/N]: ")? {
            Some(SecretStr::new(read_secret("key passphrase: ", false)?))
        } else {
            None
        };
        Ok(bastion::BastionAuthInput::Key {
            pem: SecretBytes::new(pem),
            passphrase,
        })
    } else {
        let pw = read_secret("bastion password: ", input.password_stdin)?;
        Ok(bastion::BastionAuthInput::Password(SecretStr::new(pw)))
    }
}

pub fn add_bastion(t: Target, input: BastionInput) -> Result<()> {
    let auth = resolve_bastion_auth(&input)?;
    let fingerprint = input
        .fingerprints
        .first()
        .map(|s| parse_fingerprint(s))
        .transpose()?;
    bastion::add(
        t.state_dir,
        t.ks,
        bastion::BastionAddArgs {
            name: &input.name,
            host: &input.host,
            port: input.port,
            ssh_user: &input.ssh_user,
            auth,
            fingerprint,
        },
    )
}

pub fn add_credential(t: Target, name: &str, user: &str, password_stdin: bool) -> Result<()> {
    let pw = read_secret("backend password: ", password_stdin)?;
    cred::add(t.state_dir, t.ks, name, user, SecretStr::new(pw))
}

pub fn rotate_credential(t: Target, name: &str, password_stdin: bool) -> Result<()> {
    let pw = read_secret("new backend password: ", password_stdin)?;
    cred::rotate(t.state_dir, t.ks, name, SecretStr::new(pw))
}

/// Non-secret inputs for adding an env. `backend_port` defaults to the engine's
/// conventional port when `None`.
pub struct EnvInput {
    pub name: String,
    pub backend_host: String,
    pub backend_port: Option<u16>,
    pub engine: EngineKind,
    pub database: Option<String>,
    pub bastion: Option<String>,
    pub credential: String,
    pub policy: Policy,
    pub listen_port: Option<u16>,
    pub max_pool: Option<u32>,
}

pub fn add_env(t: Target, input: EnvInput) -> Result<envs::NewEnvOutput> {
    let engine = input.engine;
    envs::add(
        t.state_dir,
        t.ks,
        envs::EnvAddArgs {
            name: &input.name,
            backend_host: &input.backend_host,
            backend_port: input.backend_port.unwrap_or_else(|| engine.default_port()),
            default_database: input.database.as_deref(),
            bastion: input.bastion.as_deref(),
            credential: &input.credential,
            policy: input.policy,
            listen_port: input.listen_port,
            max_pool: input.max_pool,
            engine,
        },
    )
}

pub fn grant(t: Target, env: &str) -> Result<envs::NewEnvOutput> {
    envs::grant(t.state_dir, t.ks, env)
}

/// A rendered service-manager artifact plus the operator steps that apply it.
pub struct ServiceArtifact {
    pub artifact: String,
    pub steps: String,
}

/// Render the platform's service artifact. `fixed_user` selects the
/// named-system-user systemd unit (the wizard's model) over the `DynamicUser`
/// default; it has no effect on macOS/Windows, whose account models are fixed.
pub fn build_service_artifact(params: &InstallParams, fixed_user: bool) -> Result<ServiceArtifact> {
    let (artifact, steps) = if cfg!(target_os = "linux") {
        if fixed_user {
            (
                installer::systemd_unit_fixed_user(params),
                installer::linux_operator_steps_fixed_user(params),
            )
        } else {
            (
                installer::systemd_unit(params),
                installer::linux_operator_steps(params),
            )
        }
    } else if cfg!(target_os = "macos") {
        (
            installer::launchd_plist(params),
            installer::macos_account_steps(params),
        )
    } else if cfg!(windows) {
        (
            installer::windows_install_ps1(params),
            "# Windows — run the generated script elevated (Administrator).".to_string(),
        )
    } else {
        bail!("unsupported platform for install-service");
    };
    Ok(ServiceArtifact { artifact, steps })
}

pub fn write_service_artifact(path: &Path, artifact: &str, force: bool) -> Result<()> {
    if path.exists() && !force {
        bail!("{} exists; pass --force to overwrite", path.display());
    }
    std::fs::write(path, artifact).with_context(|| format!("write {}", path.display()))
}

/// The mwsqld binary that should run as the service: a sibling of the running
/// mwsqlctl executable. Absolute (via `current_exe`), so it survives `sudo`.
pub fn default_daemon_path() -> Result<PathBuf> {
    let me = std::env::current_exe().context("resolve current exe")?;
    let dir = me
        .parent()
        .ok_or_else(|| anyhow!("exe has no parent dir"))?;
    let name = if cfg!(windows) {
        "mwsqld.exe"
    } else {
        "mwsqld"
    };
    Ok(dir.join(name))
}

pub fn read_secret(prompt: &str, from_stdin: bool) -> Result<String> {
    if from_stdin {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        Ok(s.trim_end_matches(['\n', '\r']).to_string())
    } else if std::io::stdin().is_terminal() {
        Ok(rpassword::prompt_password(prompt)?)
    } else {
        bail!("stdin is not a terminal; pass --password-stdin");
    }
}

pub fn read_yes_no(prompt: &str) -> Result<bool> {
    if !std::io::stdin().is_terminal() {
        return Ok(false);
    }
    eprint!("{prompt}");
    use std::io::BufRead;
    let stdin = std::io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

pub fn parse_fingerprint(s: &str) -> Result<HostKeyFingerprint> {
    let (algo, b64) = s
        .split_once(':')
        .ok_or_else(|| anyhow!("fingerprint must be <algo>:<sha256_b64>"))?;
    Ok(HostKeyFingerprint {
        algo: algo.to_string(),
        sha256_b64: b64.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mw_core::secret::SecretStr;
    use mw_core::state::KeystoreChoice;
    use tempfile::TempDir;

    fn target_dir() -> (TempDir, KeystoreChoice) {
        let tmp = TempDir::new().unwrap();
        let ks = KeystoreChoice::default_file(tmp.path());
        (tmp, ks)
    }

    #[test]
    fn is_initialized_tracks_init() {
        let (tmp, ks) = target_dir();
        let t = Target::new(tmp.path(), &ks);
        assert!(!is_initialized(tmp.path()));
        init(t).unwrap();
        assert!(is_initialized(tmp.path()));
    }

    #[test]
    fn add_round_trip_via_ops() {
        let (tmp, ks) = target_dir();
        let t = Target::new(tmp.path(), &ks);
        init(t).unwrap();

        // Drive ops::add_bastion via a key file: no stdin read, and a
        // non-terminal stdin makes the passphrase prompt return false.
        let key = tmp.path().join("id_ed25519");
        std::fs::write(
            &key,
            b"-----BEGIN OPENSSH PRIVATE KEY-----\nDUMMY\n-----END OPENSSH PRIVATE KEY-----\n",
        )
        .unwrap();
        add_bastion(
            t,
            BastionInput {
                name: "jump".into(),
                host: "h".into(),
                port: 22,
                ssh_user: "u".into(),
                key_file: Some(key),
                password_stdin: false,
                fingerprints: vec![],
            },
        )
        .unwrap();

        // The credential carries a secret, so seed it directly rather than
        // through the prompting wrapper.
        cred::add(tmp.path(), &ks, "ro", "dbuser", SecretStr::new("pw")).unwrap();

        let out = add_env(
            t,
            EnvInput {
                name: "stage".into(),
                backend_host: "db".into(),
                backend_port: None,
                engine: EngineKind::MySql,
                database: None,
                bastion: Some("jump".into()),
                credential: "ro".into(),
                policy: Policy::ReadOnly,
                listen_port: None,
                max_pool: None,
            },
        )
        .unwrap();

        assert!(!out.token.expose().is_empty());
        // NewEnvOutput carries engine + database so callers can render an
        // engine-correct connection URI without re-reading the config.
        assert_eq!(out.engine, EngineKind::MySql);
        assert_eq!(out.database, None);
        let envs = envs::list(tmp.path(), &ks).unwrap();
        assert_eq!(envs.len(), 1);
        assert_eq!(envs[0].name, "stage");
        assert_eq!(envs[0].bastion.as_deref(), Some("jump"));
        // default backend port followed the engine.
        assert_eq!(envs[0].backend, "db:3306");

        // Single-unseal path (what the wizard's "show current" uses): all three
        // lists built from one loaded config match the per-list unseals.
        let cfg = mw_core::state::load_config(tmp.path(), &ks).unwrap();
        let (br, cr, er) = (bastion::rows(&cfg), cred::rows(&cfg), envs::rows(&cfg));
        assert_eq!(br.len(), 1);
        assert_eq!(br[0].name, "jump");
        assert_eq!(cr.len(), 1);
        assert_eq!(cr[0].name, "ro");
        assert_eq!(er.len(), 1);
        assert_eq!(er[0].name, "stage");
    }

    #[test]
    fn default_daemon_path_is_absolute() {
        // Sibling of the test binary — always an absolute path.
        assert!(default_daemon_path().unwrap().is_absolute());
    }

    #[test]
    fn parse_fingerprint_splits_on_first_colon() {
        let fp = parse_fingerprint("ssh-ed25519:AAAAbase64==").unwrap();
        assert_eq!(fp.algo, "ssh-ed25519");
        assert_eq!(fp.sha256_b64, "AAAAbase64==");
        assert!(parse_fingerprint("nocolon").is_err());
    }
}
