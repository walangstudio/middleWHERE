# middleWHERE

[![version](https://img.shields.io/github/v/release/walangstudio/middleWHERE?sort=semver)](https://github.com/walangstudio/middleWHERE/releases/latest)
![license](https://img.shields.io/badge/license-MIT-green)
![rust](https://img.shields.io/badge/rust-1.78%2B-orange)
![tests](https://img.shields.io/badge/tests-300%20passing-brightgreen)

middleWHERE sits between whoever runs queries and your real database. The
caller connects to a local port with a name and a token, and runs SQL. They
never see the database host, the username, the password, or how the connection
is made.

## Why

Handing database access to tools and AI agents usually means handing them real
credentials in a config file or an environment variable. Anything that logs its
arguments or summarizes its context can leak them.

middleWHERE fixes this in two ways:

- **The caller learns nothing about the backend.** It gets an environment name
  like `staging1` and a token. The real host, user, and password stay inside
  the daemon and are never sent to the client.
- **Read-only is enforced here, not at the database.** Every statement is
  parsed. Writes, DDL, multi-statement payloads, and dangerous functions are
  rejected before they reach the backend, no matter what the backend account
  is allowed to do.

A confused script or a prompt-injected agent cannot change your data or learn
where it lives.

## What works with it

- PostgreSQL 12 to 17 (including Supabase)
- MySQL 5.6 to 9.x, MariaDB 10 and 11

Connect with what you already use. Verified: `psql`, pgAdmin, `mysql`, MySQL
Workbench, DBeaver, JDBC (pgjdbc, mysql-connector-j).

Log in with the environment name as the username and the token as the
password. The local port is loopback-only and has no TLS, so turn SSL off in
the client.

## The three binaries

No extra runtime, no DLLs.

- `mwsqld` is the daemon. It holds the sealed config and the master key, opens
  one local port per environment, checks every query, and writes the audit
  log. It runs as a system service, including on Windows.
- `mwsqlctl` is the admin tool: bastions, credentials, environments, tokens,
  audit tail, service files. Against a running service it applies each change
  live over a local admin channel, no elevation needed. `--user` and
  `--offline` edit the sealed config file directly instead.
- `mwsql` is an optional client wrapper for MySQL. It keeps your token in the
  OS keyring so you do not paste it every time. Any native client works too.

## Install

Download the archive for your platform from the
[Releases](https://github.com/walangstudio/middleWHERE/releases) page, check
the SHA-256, and extract the three binaries anywhere you like.

Linux / macOS:

```sh
ver=v0.4.0; target=x86_64-unknown-linux-gnu      # or aarch64-…, x86_64-apple-darwin, aarch64-apple-darwin
curl -fsSLO "https://github.com/walangstudio/middleWHERE/releases/download/${ver}/middlewhere-${ver}-${target}.tar.gz"
curl -fsSLO "https://github.com/walangstudio/middleWHERE/releases/download/${ver}/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS         # macOS: shasum -a 256 -c SHA256SUMS
tar -xzf "middlewhere-${ver}-${target}.tar.gz" -C /opt/middlewhere   # or any dir on your PATH
```

Windows (PowerShell):

```powershell
$ver = 'v0.4.0'; $target = 'x86_64-pc-windows-msvc'
$asset = "middlewhere-$ver-$target.zip"
irm "https://github.com/walangstudio/middleWHERE/releases/download/$ver/$asset" -OutFile $asset
irm "https://github.com/walangstudio/middleWHERE/releases/download/$ver/SHA256SUMS" -OutFile SHA256SUMS
$expected = (Select-String -Path SHA256SUMS -Pattern ([regex]::Escape($asset))).Line.Split(' ')[0]
if ((Get-FileHash $asset -Algorithm SHA256).Hash -ne $expected) { throw "Checksum mismatch for $asset" }
Expand-Archive $asset -DestinationPath C:\middlewhere -Force
```

The archive holds only the binaries. Nothing is registered or started yet.
`mwsqlctl init` installs the managed service; `mwsqld run` runs it by hand.
Or build from source (see [Build and test](#build-and-test)). Windows release
binaries are unsigned, so SmartScreen may warn at first.

## Getting started

### The guided way

```sh
./mwsqlctl init
```

`init` installs middleWHERE as a service. It self-elevates (asking first),
creates the `mwsqld` system account, seeds the sealed config, writes a
hardened service unit, starts it, and adds you to the `middlewhere-admins`
group so you can configure it later without `sudo` (log in again for the
membership to take effect).

`init` then asks **Configure connections now?** Answer yes and it walks you
through bastions, credentials, and environments right there, still elevated,
and restarts the service at the end to apply them. Passwords are prompted and
masked, never typed on the command line.

To add or change connections later, run the wizard on its own. This form
talks to the running daemon and applies each change live, no restart:

```sh
mwsqlctl wizard
```

After you add an environment the wizard validates it: it opens the bastion
tunnel and logs in to the real database. If that fails it tells you why and
offers to keep, edit, or discard the entry. Re-check any time:

```sh
mwsqlctl env test <env>      # or --all
```

### Per-user, no service

Handy for local development. No elevation, OS keychain instead of a key file:

```sh
mwsqlctl --user init       # seed a per-user config
mwsqlctl --user wizard     # add bastions / credentials / environments
mwsqld   --user run        # run the daemon yourself
```

### Uninstall

`uninstall` is the inverse of `init`: it stops and removes the service and
wipes the sealed config and master key. It confirms first; `--yes` skips the
prompt in scripts. The audit log is **kept** by default, for compliance and
forensics; `--purge-audit` deletes that too.

```sh
mwsqlctl uninstall              # service deployment (self-elevates)
mwsqlctl --user uninstall       # per-user deployment
mwsqlctl uninstall --purge-audit  # also delete the audit log
```

### The manual way

The wizard just runs the commands below. Script them directly if you prefer.

`init` is the one privileged step. It seeds the state dir
(`/var/lib/middlewhere` on Linux, `/Library/Application Support/middlewhere`
on macOS, `C:\ProgramData\middlewhere` on Windows), locked to the service
account, with the master key in a locked file (`--file-keystore` is the
service default; a daemon account has no login session to reach an OS
keychain).

```sh
./mwsqlctl init           # self-elevates; installs + starts the mwsqld service
```

Once the service is up, run the configure commands below flagless: no `sudo`,
no `--state-dir`. They go to the running daemon over its admin channel, which
validates, re-seals, and applies each change live. You must be in the
`middlewhere-admins` group (or root).

Passing an explicit `--state-dir` means "edit this config file directly",
which would silently diverge from what the daemon is serving, so mutations
with `--state-dir` are refused while the service runs. The recovery path when
the service is stopped is `--offline` from an elevated shell:

```sh
sudo mwsqlctl --offline --state-dir /var/lib/middlewhere --file-keystore env add ...
```

`--user` targets the per-user dir (`~/.local/state/middlewhere` on Linux,
honoring `$XDG_STATE_HOME`; `~/Library/Application Support/middlewhere` on
macOS; `%LOCALAPPDATA%\middlewhere` on Windows) and the OS keychain.

To avoid repeating flags, export them once:

```sh
export MW_STATE_DIR=/var/lib/middlewhere MW_FILE_KEYSTORE=1
```

If you run `mwsqld` by hand, it and `mwsqlctl` must resolve the same state
dir: same default, same `MW_STATE_DIR`, or same `--state-dir` on both.
Flagless service config needs none of this; it dials the daemon's socket.

### The quick way: one command from a connection URL

If you already have a connection string, which is what Supabase, Neon, RDS, and
most `docker-compose` files hand you, pass it straight to `env add`. It fills in
the engine, host, port, and database, stores the login as a credential named
after the env, and prints the client token:

```sh
mwsqlctl env add staging1 --url 'postgresql://appuser@db.internal:5432/app' --listen-port 6433
# backend password: (typed, hidden)
```

Leave the password out of the URL, as above, and you are prompted for it with
echo off. A password inside the URL works but lands in your shell history, so
the command warns and you should rotate it. For scripts, pass
`--password-stdin` and feed it in (see
[Scripting credential setup](#scripting-credential-setup)).

Add `--bastion <name>` if the database sits behind a jump host. Use the longer
form below when several environments share one login, or when you want a
credential name of your own.

### A worked example

Two SSH jump hosts (staging and prod), two staging databases sharing one
login, a production database behind its own jump host, and a local database
in Docker. Values in `<angle brackets>` are yours; everything else is
literal. Commands are shown flagless (live, against the running service);
add `--user` for a per-user deployment.

**Bastions.** Add the jump hosts. Pinning the host key (`--fingerprint`)
makes a swapped jump host fail closed. One pin per bastion. Run without a
password flag and you are prompted with echo off, so nothing secret reaches
shell history or the process table:

```sh
mwsqlctl bastion add <staging-bastion> --host <jump.staging.example> --ssh-user <tunnel-user> \
  --fingerprint ssh-ed25519:<sha256-b64>
# bastion password: (typed, hidden)

mwsqlctl bastion add <prod-bastion> --host <jump.prod.example> --ssh-user <prod-tunnel-user> \
  --fingerprint ssh-ed25519:<sha256-b64>
```

For CI, `--password-stdin` reads the secret from stdin instead; see
[Scripting credential setup](#scripting-credential-setup).

SSH key auth (`--key-file`) is accepted and stored but not functional yet;
the CLI warns when you use it. Use password bastions for now.

**Credentials.** A credential is a backend database user plus its password.
The two staging environments will share this one:

```sh
mwsqlctl cred add <staging-cred> --db-user <db-user>
# backend password: (typed, hidden)
```

Production uses the same username with a different password. That is simply a
second credential:

```sh
mwsqlctl cred add <prod-cred> --db-user <db-user>
```

And the local Docker database's login:

```sh
mwsqlctl cred add <local-cred> --db-user <db-user>
```

**Environments.** The two staging envs name the same credential and bastion,
so they share that login and jump host. Each still gets its own port and its
own client token, and rotating `<staging-cred>` updates both. Sharing is by
name; two credentials that happen to hold the same database user are not
shared.

```sh
mwsqlctl env add <staging-1> \
  --engine <mysql|postgres> --backend-host <db1.staging.internal> --database <app> \
  --credential <staging-cred> --bastion <staging-bastion> --listen-port <6433>

mwsqlctl env add <staging-2> \
  --engine <mysql|postgres> --backend-host <db2.staging.internal> --database <app> \
  --credential <staging-cred> --bastion <staging-bastion> --listen-port <6434>
```

Production names its own credential and bastion, so it stays fully separate:

```sh
mwsqlctl env add <prod> \
  --engine <mysql|postgres> --backend-host <db.prod.internal> --database <app> \
  --credential <prod-cred> --bastion <prod-bastion> --listen-port <6543>
```

The local Docker database needs no jump host. Omit `--bastion` and point at
loopback:

```sh
mwsqlctl env add <local> \
  --engine <mysql|postgres> --backend-host 127.0.0.1 --backend-port <3306> \
  --database <app> --credential <local-cred> --listen-port <6033>
```

`env add` validates the connection and exits non-zero if the backend is
unreachable. The env is still saved, so fix the problem and re-check with
`mwsqlctl env test <env>`. Pass `--no-validate` to skip the probe.

Every env starts read-only. Allow writes at creation with
`--policy read-write`, or flip it later:

```sh
mwsqlctl policy <env> --read-write --i-know-what-im-doing
```

### Seeing and changing what you added

List what is configured. Secrets are never printed:

```sh
mwsqlctl env list        # name, backend, engine, policy, bastion, credential, port
mwsqlctl cred list       # name and backend username only
mwsqlctl bastion list    # name, ssh endpoint, auth kind, number of pinned keys
```

Remove things. A bastion or credential still referenced by an environment is
refused, so remove the environment first:

```sh
mwsqlctl env rm <env>
mwsqlctl cred rm <credential>
mwsqlctl bastion rm <bastion>
```

Read the audit log. Every query decision and every admin action is one JSON
line; this prints the tail:

```sh
mwsqlctl audit-tail            # last 20 events
mwsqlctl audit-tail -n 200     # last 200
```

In service mode the log lives in a root-owned directory, so `audit-tail` asks
the daemon for it rather than reading the file itself. That means it works
without `sudo`.

### Migrating an existing deployment

If you already run a `.env` plus `secrets/` layout, import it in one step
instead of re-entering everything:

```sh
mwsqlctl import --from-dir /path/to/deployment
```

Import refuses to overwrite: a name or listen port that already exists is an
error, so clear the target first or rename.

### Scripting credential setup

Interactive prompts are right for humans. For CI, pass `--password-stdin` and
feed the secret from a file you create out-of-band and destroy after. Never
inline the secret on the command line; it lands in shell history.

```sh
# Linux / macOS. tmpfs keeps it off disk; shred removes the trace.
umask 077
printf '%s' "$SECRET_FROM_VAULT" > /dev/shm/pw   # injected by your CI secret store
mwsqlctl cred add <staging-cred> --db-user <db-user> --password-stdin < /dev/shm/pw
shred -u /dev/shm/pw
```

```powershell
# Windows (PowerShell 7+). On Windows PowerShell 5.1 wrap in: cmd /c "mwsqlctl ... < pw.txt"
$env:SECRET_FROM_VAULT | Out-File -NoNewline -Encoding ascii pw.txt
mwsqlctl `
  cred add <staging-cred> --db-user <db-user> --password-stdin < pw.txt
Remove-Item pw.txt
```

`--password-stdin` keeps the secret out of the process table; the file keeps
it out of shell history. Do both.

### Handing out access

Each env has one token, and the token is all a caller ever holds. Mint it for
whoever needs the env; rotating it kills the old one:

```sh
mwsqlctl grant <staging-1>
```

This prints the token once, plus the exact fields for a GUI client and a
paste-ready connection URL.

### Running queries

Start the daemon (foreground, or as the service):

```sh
mwsqld --state-dir <state-dir> --file-keystore run
```

Connect with any client. `env add` and `grant` print the fields, so nothing
needs translating:

```
  DBeaver / any SQL client — enter these fields:
    Host:      127.0.0.1
    Port:      6433
    Database:  app
    Username:  staging-1
    Password:  <token>
    SSL:       off / disable

  paste-ready URL (embeds the token — treat it like the password):
    postgresql://staging-1:<token>@127.0.0.1:6433/app?sslmode=disable
```

With `psql`:

```sh
PGPASSWORD=<token> psql -h 127.0.0.1 -p <6433> -U <staging-1> -d <app> -c 'SELECT 1'
```

Or the MySQL wrapper, which remembers the token:

```sh
mwsql login <staging-1> --port <6433>
mwsql <staging-1> -e "SELECT count(*) FROM <table>"
mwsql logout <staging-1>          # forget the stored token
```

`mwsql login` reads the token interactively; `--token-stdin` takes it on stdin
for scripts. `mwsql <env>` is shorthand for `mwsql run <env>`, and with no `-e`
it reads one statement from stdin.

Under read-only policy a write comes back denied, not executed, and the
denial lands in the audit log.

## State directory

Created by `mwsqlctl init`. Only the audit log is readable plaintext, and it
holds no secrets.

| File | Contents |
| --- | --- |
| `config.sealed` | All credentials, bastion keys, and environment definitions, sealed with ChaCha20-Poly1305. |
| `config.sealed.bak` | The previous sealed copy, kept for atomic writes. |
| `master.key` | Present with the file keystore (the service default), locked to the owner. With `--user` the key lives in the OS keychain and there is no file. |
| `audit/audit.jsonl.YYYY-MM-DD` | One JSON line per query: decision, statement hash, row count, duration. No statement text, no secrets. |

## Running as a service

`mwsqlctl init` is the one-command path; see
[Getting started](#getting-started). To run in the foreground instead:

```sh
sudo mwsqld --state-dir <state-dir> --file-keystore run
```

`run` takes three optional flags:

| Flag | Default | What it does |
| --- | --- | --- |
| `--listen-host <addr>` | `127.0.0.1` | Address the env listeners bind. Loopback is the safe default; a non-loopback bind exposes tokens on the wire and is refused for PostgreSQL unless you set `MIDDLEWHERE_ALLOW_INSECURE_PG_CLEARTEXT=1`. |
| `--allow-tofu` | off | Accept an unpinned bastion's host key on first use instead of refusing. Convenient for capturing a fingerprint to pin; insecure to leave on, since it is exactly the moment a machine-in-the-middle would be accepted. |
| `--idle-timeout-secs <n>` | per-env, 300 | Override every env's idle backend timeout. `0` disables reaping. An in-flight query is never interrupted. |

For full control, `mwsqlctl install-service` generates the platform file (a
systemd unit with `DynamicUser=yes`, a launchd plist, or a Windows PowerShell
script) and you apply it yourself. It never escalates or enables anything on
its own.

Linux:

```sh
# 1. Generate the unit (prints to stdout; --write needs an already-elevated shell):
sudo mwsqlctl install-service \
  --service-name mwsqld \
  --exec-path /usr/local/bin/mwsqld \
  --state-dir <state-dir> --file-keystore \
  --write /etc/systemd/system/mwsqld.service

# 2. Enable and start it:
sudo systemctl daemon-reload
sudo systemctl enable --now mwsqld
sudo systemctl status mwsqld
```

macOS (launchd):

```sh
# 1. Generate the plist (run on a Mac; --write needs sudo):
sudo mwsqlctl install-service \
  --service-name mwsqld \
  --exec-path /usr/local/bin/mwsqld \
  --state-dir <state-dir> --file-keystore \
  --write com.middlewhere.mwsqld.plist

# 2. The emitted file's leading comments include the one-time steps to create the
#    dedicated `_middlewhere` account and lock the state dir; run them, then:
sudo install -m0644 com.middlewhere.mwsqld.plist \
  /Library/LaunchDaemons/com.middlewhere.mwsqld.plist
sudo launchctl load -w /Library/LaunchDaemons/com.middlewhere.mwsqld.plist
```

Windows, in an elevated PowerShell:

```powershell
# 1. Generate the install script (on the target host):
mwsqlctl install-service `
  --service-name mwsqld `
  --exec-path 'C:\Program Files\middleWHERE\mwsqld.exe' `
  --state-dir <state-dir> --file-keystore `
  --write install-mwsqld.ps1

# 2. Run it elevated. It registers the service under the NT SERVICE\mwsqld
#    virtual account, locks the state dir to that account + Administrators,
#    and sets auto-start + restart-on-fail:
.\install-mwsqld.ps1
sc.exe start mwsqld
```

On Windows the sealed config must be initialized as the service account (or
pre-seeded) before first start; the generated script prints the exact
`mwsqlctl ... init` line to run.

The daemon then runs as an account your client user cannot read, so the
master key and sealed config stay out of reach. The reference files and the
reasoning live in `installers/`.

### Admin control channel

`mwsqlctl` applies config changes through a local admin channel the daemon
exposes: a Unix socket (`/run/middlewhere/mwsqld.sock`, `/var/run/…` on
macOS) or a Windows named pipe (`\\.\pipe\middlewhere-mwsqld-control`). The
daemon owns the master key, so it re-seals and applies each change itself.
The CLI never elevates, and no config file is left root-owned.

Callers are authorized by kernel peer credentials: `SO_PEERCRED` on Linux,
`getpeereid` on macOS, `ImpersonateNamedPipeClient` plus
`CheckTokenMembership` on Windows. Access is limited to root/Administrators,
the service account, and the `middlewhere-admins` group; everyone else is
denied at the door. Every mutation, denial, and read is written to the audit
log with the peer's OS identity. The channel is local-only; there is no
remote administration. When the daemon is stopped, `mwsqlctl --offline` edits
the sealed config directly from an elevated shell.

Service mode must use `--file-keystore`: the daemon account has no login
session, so the OS keyring is unreachable. The master key lives in a
`0700`/ACL-locked state dir instead.

For a non-loopback PostgreSQL bind the daemon refuses cleartext auth unless
you set `MIDDLEWHERE_ALLOW_INSECURE_PG_CLEARTEXT=1`. Use a tunnel instead.

## Build and test

Rust 1.78 or newer.

```sh
cargo build --release
cargo test --workspace
```

Tests that need a live database are skipped unless you point them at one:

```sh
MYSQL_TEST_URL='mysql://user:pass@127.0.0.1:3306/db' \
PG_TEST_URL='postgres://user:pass@127.0.0.1:5432/db' \
cargo test --workspace
```

Two host settings are pinned in `.cargo/config.toml`:
`http.check-revoke = false` (Windows schannel cannot reach the revocation
endpoints here) and `AWS_LC_SYS_PREBUILT_NASM = 1` (builds the crypto
dependency without a NASM install).

## Versioning

One version in `Cargo.toml` covers all three binaries; `--version` reports
it. Before 1.0, minor versions may break compatibility and patch versions are
fixes only. See [CHANGELOG.md](CHANGELOG.md).

## Good to know

- PostgreSQL prepared statements and parameters work. Parameters are inlined
  and run through the simple-query path, so there are no server-side cursors
  (`maxRows` is ignored, the whole result comes back) and no `COPY`.
- MySQL handles normal queries. No server-side prepared statements; client-side
  prepared statements (the Connector/J default) work.
- The local port has no TLS because it is loopback-only. Turn SSL off client
  side.
- Read-only is the default and is enforced for every client, whatever the
  backend account can do.
- Config changes from `mwsqlctl` or the standalone wizard apply live over the
  admin channel, no restart. The wizard inside `init` applies its changes with
  one service restart at the end. `--user`/`--offline` edit the sealed config
  file directly.
- Re-pinning a bastion's host key takes effect without a restart: the daemon
  forgets the cached SSH session, so new connections reconnect under the new
  pin. Sessions already running finish on the old tunnel. If an environment
  cannot reconnect under the new pin it is stopped rather than left on the old
  one, and the command tells you which went offline.
- Idle backend connections are dropped after 5 minutes of no activity (per-env
  `idle_timeout_secs`, default 300s; `mwsqld run --idle-timeout-secs <N>`
  overrides every env, `0` disables). An in-flight query is never interrupted.
- SSH bastions use password auth today. Key auth and auto-reconnect are not
  wired yet.

## License

MIT. See [LICENSE](LICENSE).
