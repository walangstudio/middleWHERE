//! Round-trip a realistic multi-env config through the seal layer.
//! Covers three capabilities that a flat env-file deployment can't do cleanly:
//!
//! - same backend username with different passwords across envs
//! - shared bastion across envs
//! - shared credential across envs
//!
//! Also asserts no plaintext password material survives on disk.

use mw_core::config::*;
use mw_core::keyring::{FileStore, MasterKeyStore};
use mw_core::seal::{seal, unseal, MasterKey, Passphrase};
use mw_core::secret::SecretStr;

const PROD_PW: &str = "prod-secret-DO-NOT-LOG-9f7a1d";
const STAGE_PW: &str = "stage-secret-DO-NOT-LOG-2b4e8c";
const SHARED_PW: &str = "shared-app-secret-c6e0b9";
const BASTION_PW: &str = "bastion-secret-7d3a1e";

fn sample_config() -> Config {
    use std::collections::BTreeMap;

    let mut bastions = BTreeMap::new();
    bastions.insert(
        "corp-jump".to_string(),
        Bastion {
            host: "jump.corp.example".into(),
            port: 22,
            ssh_user: "tunnel".into(),
            auth: BastionAuth::Password {
                password: SecretStr::new(BASTION_PW),
            },
            pinned_host_keys: vec![HostKeyFingerprint {
                algo: "ssh-ed25519".into(),
                sha256_b64: "AAAAC3NzaC1lZDI1NTE5AAAAIExampleFingerprint".into(),
            }],
        },
    );

    let mut credentials = BTreeMap::new();
    // Two distinct credentials sharing the same backend username with different
    // passwords. v1 ProxySQL refuses this; v2 must accept it.
    credentials.insert(
        "app_read_stage".to_string(),
        Credential {
            backend_user: "app_read".into(),
            backend_password: SecretStr::new(STAGE_PW),
        },
    );
    credentials.insert(
        "app_read_prod".to_string(),
        Credential {
            backend_user: "app_read".into(),
            backend_password: SecretStr::new(PROD_PW),
        },
    );
    // A shared credential referenced by two envs.
    credentials.insert(
        "reporting".to_string(),
        Credential {
            backend_user: "reporter".into(),
            backend_password: SecretStr::new(SHARED_PW),
        },
    );

    let mut envs = BTreeMap::new();
    envs.insert(
        "stage_w9".to_string(),
        Env {
            backend_host: "db-stage.corp.example".into(),
            backend_port: 3306,
            default_database: None,
            bastion: Some("corp-jump".into()),
            credential: "app_read_stage".into(),
            policy: Policy::ReadOnly,
            client_auth: ClientAuth::NativePassword {
                double_sha1: mw_core::token::double_sha1(b"stage-token"),
            },
            listen_port: 6033,
            pool: PoolSettings::default(),
            engine: EngineKind::MySql,
        },
    );
    envs.insert(
        "prod_w9".to_string(),
        Env {
            backend_host: "db-prod.corp.example".into(),
            backend_port: 3306,
            default_database: None,
            bastion: Some("corp-jump".into()),
            credential: "app_read_prod".into(),
            policy: Policy::ReadOnly,
            client_auth: ClientAuth::NativePassword {
                double_sha1: mw_core::token::double_sha1(b"prod-token"),
            },
            listen_port: 6034,
            pool: PoolSettings::default(),
            engine: EngineKind::MySql,
        },
    );
    envs.insert(
        "stage_reports".to_string(),
        Env {
            backend_host: "db-stage.corp.example".into(),
            backend_port: 3306,
            default_database: Some("reports".into()),
            bastion: Some("corp-jump".into()),
            credential: "reporting".into(),
            policy: Policy::ReadOnly,
            client_auth: ClientAuth::NativePassword {
                double_sha1: mw_core::token::double_sha1(b"rpt1-token"),
            },
            listen_port: 6035,
            pool: PoolSettings::default(),
            engine: EngineKind::MySql,
        },
    );
    envs.insert(
        "prod_reports".to_string(),
        Env {
            backend_host: "db-prod.corp.example".into(),
            backend_port: 3306,
            default_database: Some("reports".into()),
            bastion: Some("corp-jump".into()),
            credential: "reporting".into(),
            policy: Policy::ReadOnly,
            client_auth: ClientAuth::NativePassword {
                double_sha1: mw_core::token::double_sha1(b"rpt2-token"),
            },
            listen_port: 6036,
            pool: PoolSettings::default(),
            engine: EngineKind::MySql,
        },
    );

    Config {
        schema_version: CURRENT_SCHEMA_VERSION,
        bastions,
        credentials,
        envs,
    }
}

#[test]
fn validates_clean() {
    sample_config()
        .validate()
        .expect("sample config should validate");
}

#[test]
fn rejects_unknown_credential() {
    let mut cfg = sample_config();
    cfg.envs.get_mut("prod_w9").unwrap().credential = "does_not_exist".into();
    let err = cfg.validate().unwrap_err();
    assert!(matches!(err, ConfigError::UnknownCredential(ref s) if s == "does_not_exist"));
}

#[test]
fn rejects_duplicate_listen_port() {
    let mut cfg = sample_config();
    cfg.envs.get_mut("prod_w9").unwrap().listen_port = 6033;
    let err = cfg.validate().unwrap_err();
    assert!(matches!(err, ConfigError::DuplicateListenPort(6033, _, _)));
}

#[test]
fn rejects_unknown_bastion() {
    let mut cfg = sample_config();
    cfg.envs.get_mut("prod_w9").unwrap().bastion = Some("ghost".into());
    let err = cfg.validate().unwrap_err();
    assert!(matches!(err, ConfigError::UnknownBastion(ref s) if s == "ghost"));
}

#[test]
fn roundtrip_preserves_shape_and_secrets() {
    let cfg = sample_config();
    cfg.validate().unwrap();

    let mk = MasterKey::generate();
    let pp = Passphrase::default();
    let blob = seal(&cfg, &mk, &pp).expect("seal");

    // No plaintext password material in the sealed blob.
    for needle in [PROD_PW, STAGE_PW, SHARED_PW, BASTION_PW] {
        assert!(
            !contains(&blob, needle.as_bytes()),
            "sealed blob leaked {:?}",
            needle
        );
    }
    // No plaintext identifiers either (defense-in-depth — ciborium would
    // serialize map keys verbatim if the blob were unencrypted).
    for needle in ["app_read_prod", "corp-jump", "db-prod.corp.example"] {
        assert!(
            !contains(&blob, needle.as_bytes()),
            "sealed blob leaked identifier {:?}",
            needle
        );
    }

    let back = unseal(&blob, &mk, &pp).expect("unseal");
    back.validate().unwrap();

    // Spot-check the round-trip on the same-username-different-password case.
    let stage_cred = back.credentials.get("app_read_stage").unwrap();
    let prod_cred = back.credentials.get("app_read_prod").unwrap();
    assert_eq!(stage_cred.backend_user, "app_read");
    assert_eq!(prod_cred.backend_user, "app_read");
    assert_eq!(stage_cred.backend_password.expose(), STAGE_PW);
    assert_eq!(prod_cred.backend_password.expose(), PROD_PW);
    assert_ne!(
        stage_cred.backend_password.expose(),
        prod_cred.backend_password.expose(),
        "different passwords for the same backend user must survive a round-trip"
    );

    // Shared bastion + shared credential references survive.
    assert_eq!(
        back.envs.get("stage_w9").unwrap().bastion.as_deref(),
        Some("corp-jump")
    );
    assert_eq!(
        back.envs.get("prod_w9").unwrap().bastion.as_deref(),
        Some("corp-jump")
    );
    assert_eq!(
        back.envs.get("stage_reports").unwrap().credential,
        "reporting"
    );
    assert_eq!(
        back.envs.get("prod_reports").unwrap().credential,
        "reporting"
    );

    let bastion_pw = match &back.bastions.get("corp-jump").unwrap().auth {
        BastionAuth::Password { password } => password.expose().to_string(),
        _ => panic!("expected password auth"),
    };
    assert_eq!(bastion_pw, BASTION_PW);
}

#[test]
fn wrong_passphrase_rejected() {
    let cfg = sample_config();
    let mk = MasterKey::generate();
    let blob = seal(&cfg, &mk, &Passphrase::default()).unwrap();
    let wrong = Passphrase(SecretStr::new("nope"));
    assert!(unseal(&blob, &mk, &wrong).is_err());
}

#[test]
fn filestore_persists_master_key() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileStore::new(dir.path().join("master.key"));
    let mk = MasterKey::generate();
    let original = *mk.expose();
    store.store(&mk).unwrap();
    let loaded = store.load().unwrap();
    assert_eq!(loaded.expose(), &original);
    store.delete().unwrap();
    assert!(store.load().is_err());
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
