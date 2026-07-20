# Service installers

These are reference artifacts with placeholder paths
(`/usr/local/bin/mwsqld`, `/var/lib/middlewhere`, etc.). Generate ones with
your real paths via:

    mwsqlctl --state-dir <STATE> install-service [--exec-path <BIN>] [--write <PATH>]

`install-service` only renders the artifact and prints the privileged steps.
It never escalates, registers the service, or creates accounts - those are
deliberate operator actions.

## Why service mode always uses `--file-keystore`

The threat model requires the daemon to run as an OS principal the AI/client
user cannot impersonate. Each platform's "dedicated service identity" has no
usable login session, so the OS user-bound secret store can't be reached:

- Linux `DynamicUser=yes` - transient user, no D-Bus session -> no Secret Service
- Windows `NT SERVICE\mwsqld` virtual account - no loadable DPAPI profile
- macOS `_middlewhere` daemon user - no login keychain

So the master key lives in `master.key` inside the state directory, and the
*directory's* ownership/ACL is the boundary. Protection is equivalent to a
user-bound keystore: the AI user is a different principal and cannot read a
0400 file in a 0700 directory it does not own. The OS keystore remains the
path for interactive `mwsqlctl` use by an admin with a real session.

## Linux (systemd)

`DynamicUser=yes` means there is no account to create - systemd allocates a
transient unprivileged user and a `StateDirectory` (`/var/lib/middlewhere`)
owned by it at mode 0700. The unit also applies the standard sandbox
(`ProtectSystem=strict`, `NoNewPrivileges`, empty `CapabilityBoundingSet`,
`SystemCallFilter=@system-service`, `MemoryDenyWriteExecute`, ...). Only high
ports (≥6033) are bound, so no capabilities are needed.

    sudo groupadd --system middlewhere-admins   # required: the unit lists it in SupplementaryGroups
    sudo install -m0644 mwsqld.service /etc/systemd/system/mwsqld.service
    sudo systemctl daemon-reload
    sudo systemctl start mwsqld        # creates StateDirectory + RuntimeDirectory
    sudo /usr/local/bin/mwsqld --state-dir /var/lib/middlewhere --file-keystore init
    # add bastions/creds/envs with mwsqlctl against the same state dir, then:
    sudo systemctl enable --now mwsqld
    sudo usermod -aG middlewhere-admins "$USER"   # reach the control socket without sudo; re-login to apply

## macOS (launchd)

Create the dedicated `_middlewhere` daemon user once (see
`mwsqlctl install-service` output for the exact `dscl` block), `chown`
the state dir to it at 0700, then load the LaunchDaemon.

## Windows (SCM)

`install-service.ps1` (run elevated) creates the service bound to the
`NT SERVICE\mwsqld` virtual account - SCM provisions and manages it; no
password, no manual account. The script then `icacls`-locks the state dir to
that account + Administrators. The daemon speaks the SCM protocol via the
hidden `mwsqld service` subcommand.
