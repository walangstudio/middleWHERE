//! Service-manager artifact generators.
//!
//! These are pure string renderers — no I/O, no privilege. `install-service`
//! either prints the result with operator instructions or writes it to a
//! path. Account creation and service registration are privileged,
//! platform-fragile, and side-effecting, so we never do them ourselves: we
//! emit the exact commands and let the operator apply them with their own
//! elevation. That keeps the install auditable.
//!
//! Keystore note: every generated unit passes `--file-keystore`. A
//! `DynamicUser=yes` systemd unit, a Windows virtual service account, and a
//! macOS `_middlewhere` daemon user all lack a usable login session, so the OS
//! user-bound secret store (DPAPI / Keychain / Secret Service) can't be
//! reached. The master key therefore lives in `master.key` inside the
//! ACL-locked state dir. Protection is equivalent: the AI/client user is a
//! different OS principal and cannot read a 0400 file in a 0700 directory it
//! does not own.

pub struct InstallParams {
    pub service_name: String,
    pub exec_path: String,
    pub state_dir: String,
}

impl InstallParams {
    pub fn new(service_name: impl Into<String>, exec_path: impl Into<String>, state_dir: impl Into<String>) -> Self {
        Self { service_name: service_name.into(), exec_path: exec_path.into(), state_dir: state_dir.into() }
    }
}

/// systemd unit. `DynamicUser=yes` gives a transient, non-loginable,
/// unprivileged user that owns only the StateDirectory. The rest is the
/// standard hardening sandbox; we bind only high ports (>=6033) so no
/// capabilities are needed.
pub fn systemd_unit(p: &InstallParams) -> String {
    format!(r#"[Unit]
Description=middleWHERE secure SQL gateway daemon ({svc})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exe} run --state-dir {state} --file-keystore
Restart=on-failure
RestartSec=5

# --- dedicated unprivileged identity (the core of the trust model) ---
DynamicUser=yes
StateDirectory={svc}
StateDirectoryMode=0700
UMask=0077

# --- sandbox ---
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectClock=true
ProtectHostname=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
"#,
        svc = p.service_name,
        exe = p.exec_path,
        state = p.state_dir,
    )
}

/// macOS LaunchDaemon plist. Runs as a dedicated `_middlewhere` daemon user
/// (the operator creates it; see [`macos_account_steps`]).
pub fn launchd_plist(p: &InstallParams) -> String {
    format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.middlewhere.{svc}</string>
    <key>UserName</key>
    <string>_middlewhere</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>run</string>
        <string>--state-dir</string>
        <string>{state}</string>
        <string>--file-keystore</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Background</string>
    <key>StandardErrorPath</key>
    <string>{state}/stderr.log</string>
    <key>StandardOutPath</key>
    <string>{state}/stdout.log</string>
</dict>
</plist>
"#,
        svc = p.service_name,
        exe = p.exec_path,
        state = p.state_dir,
    )
}

/// PowerShell installer. Uses a Windows virtual service account
/// (`NT SERVICE\<svc>`) — SCM provisions and manages it; no password, no
/// manual account creation. The state dir is ACL-locked to that SID plus
/// Administrators only.
pub fn windows_install_ps1(p: &InstallParams) -> String {
    format!(r#"# Run elevated (Administrator). Installs the {svc} Windows service.
$ErrorActionPreference = 'Stop'

$svc   = '{svc}'
$exe   = '{exe}'
$state = '{state}'
$acct  = "NT SERVICE\$svc"

New-Item -ItemType Directory -Force -Path $state | Out-Null

# Create the service bound to a virtual service account.
sc.exe create $svc binPath= "`"$exe`" service --state-dir `"$state`" --file-keystore" obj= $acct start= auto
sc.exe description $svc "middleWHERE secure SQL gateway daemon"
sc.exe failure $svc reset= 86400 actions= restart/5000/restart/5000/restart/5000

# Lock the state dir: only the service account and Administrators. The
# AI/client user is a different principal and is denied by omission.
icacls $state /inheritance:r | Out-Null
icacls $state /grant:r "${{acct}}:(OI)(CI)F" | Out-Null
icacls $state /grant:r "BUILTIN\Administrators:(OI)(CI)F" | Out-Null

Write-Host "Installed. Start with:  sc.exe start $svc"
Write-Host "First run 'mwsqlctl --state-dir `"$state`" --file-keystore init' AS the service"
Write-Host "account context, or pre-seed the sealed config, before starting."
"#,
        svc = p.service_name,
        exe = p.exec_path,
        state = p.state_dir,
    )
}

pub fn linux_operator_steps(p: &InstallParams) -> String {
    format!(r#"# Linux (systemd) — run as root:
sudo install -m0644 mwsqld.service /etc/systemd/system/{svc}.service
sudo systemctl daemon-reload
# Initialize the sealed config AS the service identity. With DynamicUser the
# StateDirectory is created on first start; seed config beforehand by running
# init under a one-shot with the same DynamicUser, or start once (it will warn
# 'no envs') then use mwsqlctl against {state} as root:
sudo systemctl start {svc}
sudo {exe} --state-dir {state} --file-keystore  init   # if not yet initialized
sudo systemctl enable --now {svc}
journalctl -u {svc} -f
"#, svc = p.service_name, exe = p.exec_path, state = p.state_dir)
}

pub fn macos_account_steps(p: &InstallParams) -> String {
    format!(r#"# macOS — run as root. Create the dedicated daemon user (one time):
MAXID=$(dscl . -list /Users UniqueID | awk '{{print $2}}' | sort -n | tail -1)
NEWID=$((MAXID+1))
sudo dscl . -create /Users/_middlewhere
sudo dscl . -create /Users/_middlewhere UserShell /usr/bin/false
sudo dscl . -create /Users/_middlewhere RealName "middleWHERE daemon"
sudo dscl . -create /Users/_middlewhere UniqueID $NEWID
sudo dscl . -create /Users/_middlewhere PrimaryGroupID 1
sudo dscl . -create /Users/_middlewhere NFSHomeDirectory /var/empty
sudo mkdir -p {state}
sudo chown -R _middlewhere {state}
sudo chmod 700 {state}
sudo install -m0644 com.middlewhere.{svc}.plist /Library/LaunchDaemons/com.middlewhere.{svc}.plist
sudo launchctl load -w /Library/LaunchDaemons/com.middlewhere.{svc}.plist
"#, svc = p.service_name, state = p.state_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> InstallParams {
        InstallParams::new("mwsqld", "/usr/local/bin/mwsqld", "/var/lib/middlewhere")
    }

    #[test]
    fn systemd_has_security_directives() {
        let u = systemd_unit(&params());
        for needle in [
            "DynamicUser=yes",
            "NoNewPrivileges=true",
            "ProtectSystem=strict",
            "CapabilityBoundingSet=",
            "MemoryDenyWriteExecute=true",
            "SystemCallFilter=@system-service",
            "StateDirectory=mwsqld",
            "StateDirectoryMode=0700",
            "UMask=0077",
            "ExecStart=/usr/local/bin/mwsqld run --state-dir /var/lib/middlewhere --file-keystore",
            "WantedBy=multi-user.target",
        ] {
            assert!(u.contains(needle), "systemd unit missing {needle:?}\n---\n{u}");
        }
    }

    #[test]
    fn plist_is_wellformed_and_scoped() {
        let pl = launchd_plist(&params());
        assert!(pl.starts_with("<?xml"));
        assert!(pl.contains("<key>UserName</key>"));
        assert!(pl.contains("<string>_middlewhere</string>"));
        assert!(pl.contains("<string>--file-keystore</string>"));
        assert!(pl.contains("</plist>"));
        // crude balance check
        assert_eq!(pl.matches("<dict>").count(), pl.matches("</dict>").count());
        assert_eq!(pl.matches("<array>").count(), pl.matches("</array>").count());
    }

    #[test]
    fn windows_ps1_creates_virtual_account_and_locks_acl() {
        let ps = windows_install_ps1(&params());
        assert!(ps.contains("sc.exe create"));
        assert!(ps.contains(r"NT SERVICE\"));
        assert!(ps.contains("service --state-dir"));
        assert!(ps.contains("--file-keystore"));
        assert!(ps.contains("icacls"));
        assert!(ps.contains("/inheritance:r"));
        assert!(ps.contains(r"BUILTIN\Administrators"));
    }

    #[test]
    fn exec_path_is_substituted_everywhere() {
        let p = InstallParams::new("mwsqld", "C:\\Program Files\\middlewhere\\mwsqld.exe", "C:\\ProgramData\\middlewhere");
        let ps = windows_install_ps1(&p);
        assert!(ps.contains("C:\\Program Files\\middlewhere\\mwsqld.exe"));
        assert!(ps.contains("C:\\ProgramData\\middlewhere"));
    }
}
