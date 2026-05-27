//! Guards the checked-in reference artifacts under `installers/` against
//! drifting from the generators. If a generator changes, regenerate the
//! reference files; this test fails loudly until they match.

use std::path::PathBuf;

use mwsqlctl::installer::{launchd_plist, systemd_unit, windows_install_ps1, InstallParams};

fn workspace_root() -> PathBuf {
    // crates/mwsqlctl -> ../../
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn read(rel: &str) -> String {
    let p = workspace_root().join(rel);
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
        .replace("\r\n", "\n")
}

#[test]
fn systemd_reference_matches_generator() {
    let p = InstallParams::new("mwsqld", "/usr/local/bin/mwsqld", "/var/lib/middlewhere");
    assert_eq!(
        systemd_unit(&p).replace("\r\n", "\n"),
        read("installers/linux/mwsqld.service"),
        "installers/linux/mwsqld.service is stale — regenerate it",
    );
}

#[test]
fn launchd_reference_matches_generator() {
    let p = InstallParams::new(
        "mwsqld",
        "/usr/local/bin/mwsqld",
        "/Library/Application Support/middlewhere",
    );
    assert_eq!(
        launchd_plist(&p).replace("\r\n", "\n"),
        read("installers/macos/com.middlewhere.mwsqld.plist"),
        "installers/macos/com.middlewhere.mwsqld.plist is stale — regenerate it",
    );
}

#[test]
fn windows_reference_matches_generator() {
    let p = InstallParams::new(
        "mwsqld",
        r"C:\Program Files\middlewhere\mwsqld.exe",
        r"C:\ProgramData\middlewhere",
    );
    assert_eq!(
        windows_install_ps1(&p).replace("\r\n", "\n"),
        read("installers/windows/install-service.ps1"),
        "installers/windows/install-service.ps1 is stale — regenerate it",
    );
}
