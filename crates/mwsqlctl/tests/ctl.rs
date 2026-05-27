//! mwsqlctl integration tests.
//!
//! Drive the library functions directly (not via subprocess) for speed and
//! to keep secrets out of process args. The sealed config on disk is the
//! source of truth — each assertion reloads it.

use std::path::Path;

use tempfile::TempDir;

use mw_core::config::{BastionAuth, ClientAuth, Policy};
use mw_core::secret::{SecretBytes, SecretStr};
use mw_core::state::{init, load_config, KeystoreChoice};

use mwsqlctl::{audit_tail, bastion, cred, envs, policy};

fn fresh_state() -> (TempDir, KeystoreChoice) {
    let tmp = TempDir::new().unwrap();
    let ks = KeystoreChoice::default_file(tmp.path());
    init(tmp.path(), &ks).unwrap();
    (tmp, ks)
}

fn load(tmp: &Path, ks: &KeystoreChoice) -> mw_core::config::Config {
    load_config(tmp, ks).unwrap()
}

#[test]
fn bastion_lifecycle() {
    let (tmp, ks) = fresh_state();

    bastion::add(
        tmp.path(),
        &ks,
        bastion::BastionAddArgs {
            name: "corp-jump",
            host: "jump.corp",
            port: 22,
            ssh_user: "tunnel",
            auth: bastion::BastionAuthInput::Password(SecretStr::new("hunter2")),
            fingerprint: None,
        },
    )
    .unwrap();

    let rows = bastion::list(tmp.path(), &ks).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name, "corp-jump");
    assert_eq!(rows[0].auth_kind, "password");

    // Round-trip through the sealed config; the password should be intact.
    let cfg = load(tmp.path(), &ks);
    let b = cfg.bastions.get("corp-jump").unwrap();
    match &b.auth {
        BastionAuth::Password { password } => assert_eq!(password.expose(), "hunter2"),
        _ => panic!("expected password auth"),
    }

    // Duplicate name is rejected.
    let err = bastion::add(
        tmp.path(),
        &ks,
        bastion::BastionAddArgs {
            name: "corp-jump",
            host: "x",
            port: 22,
            ssh_user: "x",
            auth: bastion::BastionAuthInput::Password(SecretStr::new("p")),
            fingerprint: None,
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("already exists"));

    bastion::rm(tmp.path(), &ks, "corp-jump").unwrap();
    assert!(bastion::list(tmp.path(), &ks).unwrap().is_empty());
}

#[test]
fn bastion_key_auth_round_trip() {
    let (tmp, ks) = fresh_state();
    let pem =
        b"-----BEGIN OPENSSH PRIVATE KEY-----\nfake-bytes\n-----END OPENSSH PRIVATE KEY-----\n";
    bastion::add(
        tmp.path(),
        &ks,
        bastion::BastionAddArgs {
            name: "kjump",
            host: "h",
            port: 22,
            ssh_user: "u",
            auth: bastion::BastionAuthInput::Key {
                pem: SecretBytes::new(pem.to_vec()),
                passphrase: Some(SecretStr::new("kpw")),
            },
            fingerprint: None,
        },
    )
    .unwrap();
    let cfg = load(tmp.path(), &ks);
    let b = cfg.bastions.get("kjump").unwrap();
    match &b.auth {
        BastionAuth::Key {
            private_key_pem,
            passphrase,
        } => {
            assert_eq!(private_key_pem.expose(), pem);
            assert_eq!(passphrase.as_ref().unwrap().expose(), "kpw");
        }
        _ => panic!("expected key auth"),
    }
}

#[test]
fn cred_lifecycle_including_rotation() {
    let (tmp, ks) = fresh_state();
    cred::add(tmp.path(), &ks, "stage", "app_read", SecretStr::new("p1")).unwrap();
    assert_eq!(
        load(tmp.path(), &ks)
            .credentials
            .get("stage")
            .unwrap()
            .backend_password
            .expose(),
        "p1"
    );

    cred::rotate(tmp.path(), &ks, "stage", SecretStr::new("p2")).unwrap();
    assert_eq!(
        load(tmp.path(), &ks)
            .credentials
            .get("stage")
            .unwrap()
            .backend_password
            .expose(),
        "p2"
    );

    let rows = cred::list(tmp.path(), &ks).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].backend_user, "app_read");

    cred::rm(tmp.path(), &ks, "stage").unwrap();
    assert!(load(tmp.path(), &ks).credentials.is_empty());
}

#[test]
fn cred_rm_rejected_when_env_references_it() {
    let (tmp, ks) = fresh_state();
    cred::add(tmp.path(), &ks, "c1", "u", SecretStr::new("p")).unwrap();
    envs::add(
        tmp.path(),
        &ks,
        envs::EnvAddArgs {
            name: "e1",
            backend_host: "h",
            backend_port: 3306,
            default_database: None,
            bastion: None,
            credential: "c1",
            policy: Policy::ReadOnly,
            listen_port: None,
            max_pool: None,
            engine: Default::default(),
        },
    )
    .unwrap();
    let err = cred::rm(tmp.path(), &ks, "c1").unwrap_err();
    assert!(err.to_string().contains("still referenced"), "{err}");
}

#[test]
fn bastion_rm_rejected_when_env_references_it() {
    let (tmp, ks) = fresh_state();
    cred::add(tmp.path(), &ks, "c1", "u", SecretStr::new("p")).unwrap();
    bastion::add(
        tmp.path(),
        &ks,
        bastion::BastionAddArgs {
            name: "b1",
            host: "h",
            port: 22,
            ssh_user: "x",
            auth: bastion::BastionAuthInput::Password(SecretStr::new("p")),
            fingerprint: None,
        },
    )
    .unwrap();
    envs::add(
        tmp.path(),
        &ks,
        envs::EnvAddArgs {
            name: "e1",
            backend_host: "h",
            backend_port: 3306,
            default_database: None,
            bastion: Some("b1"),
            credential: "c1",
            policy: Policy::ReadOnly,
            listen_port: None,
            max_pool: None,
            engine: Default::default(),
        },
    )
    .unwrap();
    let err = bastion::rm(tmp.path(), &ks, "b1").unwrap_err();
    assert!(err.to_string().contains("still referenced"), "{err}");
}

#[test]
fn env_add_assigns_unique_ports_and_returns_a_token() {
    let (tmp, ks) = fresh_state();
    cred::add(tmp.path(), &ks, "c", "u", SecretStr::new("p")).unwrap();

    let out1 = envs::add(
        tmp.path(),
        &ks,
        envs::EnvAddArgs {
            name: "stage",
            backend_host: "h",
            backend_port: 3306,
            default_database: None,
            bastion: None,
            credential: "c",
            policy: Policy::ReadOnly,
            listen_port: None,
            max_pool: None,
            engine: Default::default(),
        },
    )
    .unwrap();
    let out2 = envs::add(
        tmp.path(),
        &ks,
        envs::EnvAddArgs {
            name: "prod",
            backend_host: "h",
            backend_port: 3306,
            default_database: None,
            bastion: None,
            credential: "c",
            policy: Policy::ReadOnly,
            listen_port: None,
            max_pool: None,
            engine: Default::default(),
        },
    )
    .unwrap();
    assert_ne!(out1.listen_port, out2.listen_port);
    assert!(out1.listen_port >= 6033 && out1.listen_port <= 6064);

    // Tokens are non-empty and distinct.
    assert!(!out1.token.expose().is_empty());
    assert_ne!(out1.token.expose(), out2.token.expose());

    // Verify the stored hash matches the returned token.
    let cfg = load(tmp.path(), &ks);
    let stage = cfg.envs.get("stage").unwrap();
    match &stage.client_auth {
        ClientAuth::NativePassword { double_sha1 } => {
            assert_eq!(
                double_sha1,
                &mw_core::token::double_sha1(out1.token.expose().as_bytes())
            );
        }
        other => panic!("expected native password, got {other:?}"),
    }
}

#[test]
fn env_add_rejects_invalid_refs() {
    let (tmp, ks) = fresh_state();
    let err = envs::add(
        tmp.path(),
        &ks,
        envs::EnvAddArgs {
            name: "e",
            backend_host: "h",
            backend_port: 3306,
            default_database: None,
            bastion: None,
            credential: "ghost",
            policy: Policy::ReadOnly,
            listen_port: None,
            max_pool: None,
            engine: Default::default(),
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("credential"));

    cred::add(tmp.path(), &ks, "c", "u", SecretStr::new("p")).unwrap();
    let err = envs::add(
        tmp.path(),
        &ks,
        envs::EnvAddArgs {
            name: "e",
            backend_host: "h",
            backend_port: 3306,
            default_database: None,
            bastion: Some("nope"),
            credential: "c",
            policy: Policy::ReadOnly,
            listen_port: None,
            max_pool: None,
            engine: Default::default(),
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("bastion"));
}

#[test]
fn env_rotate_token_invalidates_old() {
    let (tmp, ks) = fresh_state();
    cred::add(tmp.path(), &ks, "c", "u", SecretStr::new("p")).unwrap();
    let out = envs::add(
        tmp.path(),
        &ks,
        envs::EnvAddArgs {
            name: "e",
            backend_host: "h",
            backend_port: 3306,
            default_database: None,
            bastion: None,
            credential: "c",
            policy: Policy::ReadOnly,
            listen_port: None,
            max_pool: None,
            engine: Default::default(),
        },
    )
    .unwrap();
    let old = out.token.expose().to_string();
    let new = envs::rotate_token(tmp.path(), &ks, "e").unwrap();
    assert_ne!(new.expose(), old);

    let cfg = load(tmp.path(), &ks);
    let stored = match &cfg.envs.get("e").unwrap().client_auth {
        ClientAuth::NativePassword { double_sha1 } => *double_sha1,
        other => panic!("expected native password, got {other:?}"),
    };
    assert_eq!(stored, mw_core::token::double_sha1(new.expose().as_bytes()));
    assert_ne!(stored, mw_core::token::double_sha1(old.as_bytes()));
}

#[test]
fn policy_read_write_requires_confirmation() {
    let (tmp, ks) = fresh_state();
    cred::add(tmp.path(), &ks, "c", "u", SecretStr::new("p")).unwrap();
    envs::add(
        tmp.path(),
        &ks,
        envs::EnvAddArgs {
            name: "e",
            backend_host: "h",
            backend_port: 3306,
            default_database: None,
            bastion: None,
            credential: "c",
            policy: Policy::ReadOnly,
            listen_port: None,
            max_pool: None,
            engine: Default::default(),
        },
    )
    .unwrap();
    let err =
        policy::set(tmp.path(), &ks, "e", policy::PolicyTarget::ReadWrite, false).unwrap_err();
    assert!(err.to_string().contains("--i-know-what-im-doing"));

    policy::set(tmp.path(), &ks, "e", policy::PolicyTarget::ReadWrite, true).unwrap();
    let cfg = load(tmp.path(), &ks);
    assert!(matches!(
        cfg.envs.get("e").unwrap().policy,
        Policy::ReadWrite
    ));

    // Going back to ReadOnly does not require the flag.
    policy::set(tmp.path(), &ks, "e", policy::PolicyTarget::ReadOnly, false).unwrap();
    let cfg = load(tmp.path(), &ks);
    assert!(matches!(
        cfg.envs.get("e").unwrap().policy,
        Policy::ReadOnly
    ));
}

#[test]
fn audit_tail_empty_dir_yields_empty() {
    let tmp = TempDir::new().unwrap();
    let out = audit_tail::tail(tmp.path(), 10).unwrap();
    assert!(out.is_empty());
}

#[test]
fn audit_tail_reads_latest_file_last_n_lines() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("audit");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("audit.jsonl.2026-05-13"), "old1\nold2\n").unwrap();
    std::fs::write(dir.join("audit.jsonl.2026-05-14"), "a\nb\nc\nd\ne\n").unwrap();

    let out = audit_tail::tail(tmp.path(), 2).unwrap();
    assert_eq!(out, vec!["d".to_string(), "e".to_string()]);

    let out = audit_tail::tail(tmp.path(), 100).unwrap();
    assert_eq!(out.len(), 5);
}

#[test]
fn grant_rotates_token_and_reports_port() {
    let (tmp, ks) = fresh_state();
    cred::add(tmp.path(), &ks, "c", "u", SecretStr::new("p")).unwrap();
    let added = envs::add(
        tmp.path(),
        &ks,
        envs::EnvAddArgs {
            name: "stage_w9",
            backend_host: "h",
            backend_port: 3306,
            default_database: None,
            bastion: None,
            credential: "c",
            policy: Policy::ReadOnly,
            listen_port: Some(6055),
            max_pool: None,
            engine: Default::default(),
        },
    )
    .unwrap();

    let granted = envs::grant(tmp.path(), &ks, "stage_w9").unwrap();
    assert_eq!(
        granted.listen_port, 6055,
        "grant must report the env's listen port"
    );
    assert_ne!(
        granted.token.expose(),
        added.token.expose(),
        "grant rotates the token"
    );

    // The config now authenticates the NEW token, not the old one.
    let cfg = load(tmp.path(), &ks);
    let stored = match &cfg.envs.get("stage_w9").unwrap().client_auth {
        ClientAuth::NativePassword { double_sha1 } => *double_sha1,
        other => panic!("expected native password, got {other:?}"),
    };
    assert_eq!(
        stored,
        mw_core::token::double_sha1(granted.token.expose().as_bytes())
    );
    assert_ne!(
        stored,
        mw_core::token::double_sha1(added.token.expose().as_bytes())
    );
}

#[test]
fn grant_unknown_env_errors() {
    let (tmp, ks) = fresh_state();
    let err = envs::grant(tmp.path(), &ks, "ghost").unwrap_err();
    assert!(err.to_string().contains("not found"), "{err}");
}

#[test]
fn backup_present_after_first_mutation() {
    let (tmp, ks) = fresh_state();
    assert!(!tmp.path().join(mw_core::state::CONFIG_BACKUP_NAME).exists());
    cred::add(tmp.path(), &ks, "c", "u", SecretStr::new("p")).unwrap();
    assert!(tmp.path().join(mw_core::state::CONFIG_BACKUP_NAME).exists());
}
