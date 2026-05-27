//! Phase 10 importer against a synthetic POC tree.

use std::path::Path;

use tempfile::TempDir;

use mw_core::config::{BastionAuth, ClientAuth};
use mw_core::state::{init, load_config, KeystoreChoice};
use mwsqlctl::import_poc;

const ENV_FILE: &str = "\
# bastion
BASTION_STAGE_HOST=stage-bastion.example.com
BASTION_STAGE_USER=ssh_user
BASTION_STAGE_SSH_AUTH=password

# shared credential set
STAGE_USER=stage_reader

# two stage envs sharing STAGE creds, auto-matched to BASTION_STAGE by prefix
STAGE_DB1_HOST=db1.stage.internal
STAGE_DB1_CREDENTIALS=STAGE
STAGE_DB2_HOST=db2.stage.internal
STAGE_DB2_CREDENTIALS=STAGE

# inline-cred env, explicit direct, non-default port
LOCAL_HOST=host.docker.internal
LOCAL_PORT=3307
LOCAL_USER=root
LOCAL_BASTION=direct
";

fn make_poc(dir: &Path, with_known_hosts: bool) {
    std::fs::write(dir.join(".env"), ENV_FILE).unwrap();
    let s = dir.join("secrets");
    std::fs::create_dir_all(&s).unwrap();
    std::fs::write(s.join("bastion_stage_password"), "bastion-pw\n").unwrap();
    std::fs::write(s.join("stage_password"), "stage-reader-pw\n").unwrap();
    std::fs::write(s.join("local_password"), "root-pw\n").unwrap();
    if with_known_hosts {
        // A real ed25519 known_hosts-style line (host keytype base64blob).
        std::fs::write(
            s.join("bastion_stage_known_hosts"),
            "stage-bastion.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGNgHf7mF0jHBlRBaLH28f8tJDYL6e9lp+0W8APHgUQy\n",
        ).unwrap();
    }
}

fn fresh_state() -> (TempDir, KeystoreChoice) {
    let tmp = TempDir::new().unwrap();
    let ks = KeystoreChoice::default_file(tmp.path());
    init(tmp.path(), &ks).unwrap();
    (tmp, ks)
}

#[test]
fn import_maps_poc_faithfully() {
    let poc = TempDir::new().unwrap();
    make_poc(poc.path(), true);
    let (state, ks) = fresh_state();

    let report = import_poc::import(state.path(), &ks, poc.path()).unwrap();
    assert_eq!(report.bastions, vec!["stage"]);
    let mut creds = report.credentials.clone();
    creds.sort();
    assert_eq!(creds, vec!["local", "stage"]);

    let cfg = load_config(state.path(), &ks).unwrap();

    // Bastion: password auth + 1 pinned fingerprint.
    let b = cfg.bastions.get("stage").unwrap();
    assert_eq!(b.host, "stage-bastion.example.com");
    assert_eq!(b.ssh_user, "ssh_user");
    assert!(matches!(b.auth, BastionAuth::Password { .. }));
    assert_eq!(b.pinned_host_keys.len(), 1);
    assert_eq!(b.pinned_host_keys[0].algo, "ssh-ed25519");

    // Shared credential resolved once, used by both stage envs.
    let stage = cfg.credentials.get("stage").unwrap();
    assert_eq!(stage.backend_user, "stage_reader");
    assert_eq!(stage.backend_password.expose(), "stage-reader-pw");
    let local = cfg.credentials.get("local").unwrap();
    assert_eq!(local.backend_user, "root");
    assert_eq!(local.backend_password.expose(), "root-pw");

    // Envs: names verbatim, sorted listen ports 6033.. (LOCAL, STAGE_DB1, STAGE_DB2).
    let db1 = cfg.envs.get("STAGE_DB1").unwrap();
    let db2 = cfg.envs.get("STAGE_DB2").unwrap();
    let loc = cfg.envs.get("LOCAL").unwrap();
    assert_eq!(loc.listen_port, 6033);
    assert_eq!(db1.listen_port, 6034);
    assert_eq!(db2.listen_port, 6035);

    // Auto bastion-by-prefix for STAGE_DB*, explicit direct for LOCAL.
    assert_eq!(db1.bastion.as_deref(), Some("stage"));
    assert_eq!(db2.bastion.as_deref(), Some("stage"));
    assert_eq!(loc.bastion, None);

    assert_eq!(db1.credential, "stage");
    assert_eq!(db2.credential, "stage");
    assert_eq!(loc.credential, "local");

    assert_eq!(loc.backend_host, "host.docker.internal");
    assert_eq!(loc.backend_port, 3307);
    assert_eq!(db1.backend_port, 3306);

    // Every env got a fresh native-password token.
    for e in cfg.envs.values() {
        assert!(matches!(e.client_auth, ClientAuth::NativePassword { .. }));
    }
    cfg.validate().unwrap();
}

#[test]
fn missing_known_hosts_warns_unpinned() {
    let poc = TempDir::new().unwrap();
    make_poc(poc.path(), false);
    let (state, ks) = fresh_state();
    let report = import_poc::import(state.path(), &ks, poc.path()).unwrap();
    assert!(
        report.warnings.iter().any(|w| w.contains("UNPINNED")),
        "{:?}",
        report.warnings
    );
    let cfg = load_config(state.path(), &ks).unwrap();
    assert!(cfg
        .bastions
        .get("stage")
        .unwrap()
        .pinned_host_keys
        .is_empty());
}

#[test]
fn missing_password_file_errors() {
    let poc = TempDir::new().unwrap();
    make_poc(poc.path(), false);
    std::fs::remove_file(poc.path().join("secrets/stage_password")).unwrap();
    let (state, ks) = fresh_state();
    let err = import_poc::import(state.path(), &ks, poc.path()).unwrap_err();
    assert!(err.to_string().contains("stage_password"), "{err}");
}

#[test]
fn collision_with_existing_env_is_refused() {
    let poc = TempDir::new().unwrap();
    make_poc(poc.path(), false);
    let (state, ks) = fresh_state();
    import_poc::import(state.path(), &ks, poc.path()).unwrap();
    // Second import of the same POC must refuse (names already present).
    let err = import_poc::import(state.path(), &ks, poc.path()).unwrap_err();
    assert!(err.to_string().contains("already exists"), "{err}");
}

#[test]
fn parses_quotes_and_export_prefix() {
    let poc = TempDir::new().unwrap();
    std::fs::write(
        poc.path().join(".env"),
        "export DB_HOST=\"quoted.example.com\"\nDB_USER='rootish'\n",
    )
    .unwrap();
    let s = poc.path().join("secrets");
    std::fs::create_dir_all(&s).unwrap();
    std::fs::write(s.join("db_password"), "p\n").unwrap();
    let (state, ks) = fresh_state();
    import_poc::import(state.path(), &ks, poc.path()).unwrap();
    let cfg = load_config(state.path(), &ks).unwrap();
    assert_eq!(
        cfg.envs.get("DB").unwrap().backend_host,
        "quoted.example.com"
    );
    assert_eq!(cfg.credentials.get("db").unwrap().backend_user, "rootish");
}

#[test]
fn path_traversal_secret_name_refused() {
    // A hostile .env whose env prefix escapes the secrets dir.
    let poc = TempDir::new().unwrap();
    std::fs::write(
        poc.path().join(".env"),
        "../../../etc/shadow_HOST=x\n../../../etc/shadow_USER=root\n",
    )
    .unwrap();
    std::fs::create_dir_all(poc.path().join("secrets")).unwrap();
    let (state, ks) = fresh_state();
    let err = import_poc::import(state.path(), &ks, poc.path()).unwrap_err();
    assert!(err.to_string().contains("refusing secret name"), "{err}");
}
