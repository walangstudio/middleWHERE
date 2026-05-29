# middleWHERE

[![version](https://img.shields.io/github/v/release/walangstudio/middleWHERE?sort=semver)](https://github.com/walangstudio/middleWHERE/releases/latest)
![license](https://img.shields.io/badge/license-MIT-green)
![rust](https://img.shields.io/badge/rust-1.78%2B-orange)
![tests](https://img.shields.io/badge/tests-149%20passing-brightgreen)

middleWHERE sits between whoever is running queries and your real database. The
caller connects to a local port, logs in with a name and a token, and runs SQL.
They never get the database host, the username, the password, or anything about
how the connection is actually made.

## Why this exists

We kept handing database access to tools and to LLM agents, and every time it
meant handing over real credentials and connection details in some config file
or environment variable. That is exactly what you do not want sitting next to a
model that summarizes its context, or a tool that logs its arguments.

middleWHERE fixes that with two ideas:

The caller is told nothing about the backend. It gets an environment name like
`staging1` and a token. The real host, port, database user, and password stay
inside the daemon and are never sent to the client. Someone reading the client
side, a model, or a leaked log cannot learn where the data lives or how to
reach it directly.

Read-only is enforced here, not at the database. Even if the database account
behind an environment can write, middleWHERE parses every statement and rejects
writes, DDL, multi-statement payloads, and dangerous functions before they ever
reach the backend. A confused script or a prompt-injected agent cannot modify
or destroy data through it, regardless of what the underlying account is
allowed to do.

## What it supports

- PostgreSQL 12 to 17 (including Supabase).
- MySQL 5.6 to 9.x and MariaDB 10/11.

Connect with whatever you already use. These are verified working:

- `psql` and the PostgreSQL libpq family.
- pgAdmin.
- `mysql` command-line client.
- MySQL Workbench.
- DBeaver, against both engines.
- JDBC applications (pgjdbc, mysql-connector-j).

There is no TLS on the local port because it only listens on loopback, so turn
SSL off in the client. You log in with the environment name as the username and
the issued token as the password.

## How it is put together

Three binaries, no extra runtime, no DLLs:

- `mwsqld` is the daemon. It holds the sealed config, opens one local port per
  environment, checks every query, and writes the audit log. It also runs as a
  Windows service.
- `mwsqlctl` is the admin tool. You use it to set up credentials, bastions, and
  environments, to rotate tokens, to read the audit tail, and to generate the
  service files. It works offline against the sealed config.
- `mwsql` is an optional client wrapper for MySQL that keeps a token in your OS
  keyring so you do not paste it every time. Any native client works too.

## Install

Prebuilt binaries (`mwsqld`, `mwsqlctl`, `mwsql`) for Linux, macOS, and Windows
are published on the [Releases](https://github.com/walangstudio/middleWHERE/releases)
page. The installers download the archive, verify its SHA-256, and install all
three; re-running upgrades in place.

Linux / macOS:

```sh
curl -fsSL https://raw.githubusercontent.com/walangstudio/middleWHERE/main/install.sh | sh
# specific version:  ... | sh -s -- --version v0.2.0
# uninstall:         ... | sh -s -- --uninstall
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/walangstudio/middleWHERE/main/install.ps1 | iex
# specific version:  & ([scriptblock]::Create((irm https://raw.githubusercontent.com/walangstudio/middleWHERE/main/install.ps1))) -Version v0.2.0
# uninstall:         & ([scriptblock]::Create((irm https://raw.githubusercontent.com/walangstudio/middleWHERE/main/install.ps1))) -Uninstall
```

The installers place **only the binaries** — they do not register or start a
service. You run `mwsqld run` yourself, or opt into a managed service; see
[Running as a service](#running-as-a-service).

Or build from source (see [Build and test](#build-and-test)). Windows release
binaries are unsigned; SmartScreen may warn until reputation accrues.

## Getting started

Pick a state directory. The daemon and the admin tool both point at it. These
examples use `--file-keystore`, which keeps the master key in a locked file in
the state directory; drop it to use the OS keychain instead when you have a
real login session.

`init` creates the directory (and its `audit/` subdir) for you — no `mkdir`
first. **Where to put it:**

- **System service (production):** the default is a machine-wide path —
  `/var/lib/middlewhere` on Linux, `/Library/Application Support/middlewhere` on
  macOS, `%ProgramData%\middlewhere` on Windows. Creating it needs elevation, and
  it must be owned by (and readable only to) the daemon account, not your client
  user. Omit `--state-dir` to use the default.

  ```sh
  sudo mwsqlctl --state-dir /var/lib/middlewhere --file-keystore init
  sudo chmod 700 /var/lib/middlewhere   # init does not lock the dir itself; do it
  ```

- **Single user / dev (no sudo):** point it at a directory you own, e.g.
  `~/.middlewhere`. No elevation needed; the master key and sealed config are
  written owner-only regardless of the dir's mode. On a shared box, `chmod 700`
  it too so other local users can't read the audit log or file names.

  ```sh
  mwsqlctl --state-dir ~/.middlewhere --file-keystore init
  ```

That generates a master key, seals an empty config, and creates the directory
layout. Nothing is exposed in plaintext except the audit log. `init` refuses to
overwrite an existing `config.sealed`, so re-running is safe. The rest of these
examples write `<state-dir>` — substitute whichever path you chose.

Whichever you pick, the daemon and `mwsqlctl` must both be given the **same**
`--state-dir`.

### A worked example

This builds a real layout: two SSH jump hosts (one for staging, one for prod),
two staging databases that share a single login behind the staging jump host, a
production database that uses the same database username but a different
password behind its own jump host, and a local database running in Docker on
the daemon host. Values in `<angle brackets>` are yours to fill in; everything
else is literal. `<state-dir>` is wherever you ran `init`.

**Bastions.** Add the two jump hosts. Pinning the host key (`--fingerprint`)
makes a swapped jump host fail closed; repeat the flag to pin more than one key.

Run it without a password flag and `mwsqlctl` prompts for the password with echo
off — nothing secret reaches your shell history or the process table:

```sh
mwsqlctl --state-dir <state-dir> --file-keystore \
  bastion add <staging-bastion> --host <jump.staging.example> --ssh-user <tunnel-user> \
  --fingerprint ssh-ed25519:<sha256-b64>
# bastion password: ‹typed, hidden›

mwsqlctl --state-dir <state-dir> --file-keystore \
  bastion add <prod-bastion> --host <jump.prod.example> --ssh-user <prod-tunnel-user> \
  --fingerprint ssh-ed25519:<sha256-b64>
```

For unattended/CI use only, pass `--password-stdin` and feed the secret in on
stdin from a file or fd — never an inline literal, which would land in shell
history. See [Scripting credential setup](#scripting-credential-setup).

SSH **key auth** is accepted by the CLI (`--key-file <private-key.pem>`, which
replaces the password entirely) but is **not yet active at runtime** — the daemon
currently returns `ssh key auth not yet wired` (Phase 7b). Use password
bastions for now.

**Credentials.** A credential is a backend database user plus its password.
Same rule as bastions: omit the flag and the password is prompted, hidden. Add
the one login the two staging environments will share:

```sh
mwsqlctl --state-dir <state-dir> --file-keystore \
  cred add <staging-cred> --user <db-user>
# backend password: ‹typed, hidden›
```

Production uses the **same username but a different password** — that is just a
second credential entry with the same `--user` value:

```sh
mwsqlctl --state-dir <state-dir> --file-keystore \
  cred add <prod-cred> --user <db-user>
```

And the local Docker database's login:

```sh
mwsqlctl --state-dir <state-dir> --file-keystore \
  cred add <local-cred> --user <db-user>
```

**Environments.** The two staging envs name the *same* credential and the
*same* bastion, so they share that one login and jump host; each still gets its
own loopback port and its own client token. Rotating `<staging-cred>` updates
both at once. (Sharing is by naming the same credential/bastion — using the
same database username across two different credentials does *not* share them.)

```sh
mwsqlctl --state-dir <state-dir> --file-keystore env add <staging-1> \
  --engine <mysql|postgres> --backend-host <db1.staging.internal> --database <app> \
  --credential <staging-cred> --bastion <staging-bastion> --listen-port <6433>

mwsqlctl --state-dir <state-dir> --file-keystore env add <staging-2> \
  --engine <mysql|postgres> --backend-host <db2.staging.internal> --database <app> \
  --credential <staging-cred> --bastion <staging-bastion> --listen-port <6434>
```

Production names its own credential and its own bastion, so it stays fully
separate from staging:

```sh
mwsqlctl --state-dir <state-dir> --file-keystore env add <prod> \
  --engine <mysql|postgres> --backend-host <db.prod.internal> --database <app> \
  --credential <prod-cred> --bastion <prod-bastion> --listen-port <6543>
```

The local Docker database needs no jump host: omit `--bastion` and point at
loopback, and the daemon connects to it directly.

```sh
mwsqlctl --state-dir <state-dir> --file-keystore env add <local> \
  --engine <mysql|postgres> --backend-host 127.0.0.1 --backend-port <3306> \
  --database <app> --credential <local-cred> --listen-port <6033>
```

Every env defaults to `read-only`. Pass `--policy read-write` at creation, or
flip it later:

```sh
mwsqlctl --state-dir <state-dir> --file-keystore policy <env> --read-write --i-know-what-im-doing
```

### Scripting credential setup

The interactive prompt is the right default for a human. When you must automate
`bastion add` / `cred add` (CI, provisioning), pass `--password-stdin` and feed
the secret in **without** writing it on the command line — an inline
`printf '...secret...' | ...` puts the literal in your shell history.

Redirect from a file you create out-of-band and then destroy:

```sh
# Linux / macOS — tmpfs keeps it off disk; shred removes the trace.
umask 077
printf '%s' "$SECRET_FROM_VAULT" > /dev/shm/pw   # $SECRET injected by your CI secret store
mwsqlctl --state-dir <state-dir> --file-keystore \
  cred add <staging-cred> --user <db-user> --password-stdin < /dev/shm/pw
shred -u /dev/shm/pw
```

```powershell
# Windows (PowerShell 7+). On Windows PowerShell 5.1 wrap in: cmd /c "mwsqlctl ... < pw.txt"
$env:SECRET_FROM_VAULT | Out-File -NoNewline -Encoding ascii pw.txt
mwsqlctl --state-dir <state-dir> --file-keystore `
  cred add <staging-cred> --user <db-user> --password-stdin < pw.txt
Remove-Item pw.txt
```

`--password-stdin` keeps the secret out of the process table (`ps`,
`/proc/<pid>/cmdline`); reading from a file/fd instead of an inline literal
keeps it out of shell history. Do both.

### Handing out access

Each env has a token — the only thing the caller ever holds. Mint one for
whoever needs that env; rotating it kills the old one:

```sh
mwsqlctl --state-dir <state-dir> --file-keystore grant <staging-1>
```

That prints the connection line and the token.

### Running queries

Start the daemon (foreground, or as the service above):

```sh
mwsqld --state-dir <state-dir> --file-keystore run
```

Connect with any client. With `psql` against a Postgres env:

```sh
PGPASSWORD=<token> psql -h 127.0.0.1 -p <6433> -U <staging-1> -d <app> -c 'SELECT 1'
```

Or the MySQL wrapper, which remembers the token for you:

```sh
mwsql login <staging-1> --port <6433>
mwsql <staging-1> -e "SELECT count(*) FROM <table>"
```

Under the default read-only policy a write comes back as a denied query, not a
modified row, and the denial is recorded in the audit log.

## State directory

`mwsqlctl init` creates it. Only the audit log is readable plaintext, and it
holds no secrets.

| File | Contents |
| --- | --- |
| `config.sealed` | All credentials, bastion keys, and environment definitions, sealed with ChaCha20-Poly1305. |
| `config.sealed.bak` | The previous sealed copy, kept for atomic writes. |
| `master.key` | Only with `--file-keystore`, locked to the owner. Otherwise the key lives in the OS keychain and there is no file. |
| `audit/audit.jsonl.YYYY-MM-DD` | One JSON line per query: decision, statement hash, row count, duration. No statement text, no secrets. |

## Running as a service

There is no auto-installed service. The simplest way to run is in the
foreground:

```sh
mwsqld --state-dir <state-dir> --file-keystore run
```

For a managed service, `mwsqlctl install-service` *generates* the platform file
(a systemd unit with `DynamicUser=yes`, a launchd plist, or a Windows
PowerShell script) — it never escalates, enables it, or creates accounts
itself. You apply it. On Linux:

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

macOS and Windows follow the same two-step shape — `install-service` emits the
platform artifact for the OS you run it on, you apply it.

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

Windows (SCM) — run in an elevated (Administrator) PowerShell:

```powershell
# 1. Generate the install script (on the target host):
mwsqlctl install-service `
  --service-name mwsqld `
  --exec-path 'C:\Program Files\middleWHERE\mwsqld.exe' `
  --state-dir <state-dir> --file-keystore `
  --write install-mwsqld.ps1

# 2. Run it elevated. It registers the service under the NT SERVICE\mwsqld
#    virtual account, locks the state dir to that account + Administrators
#    (your client user is denied by omission), and sets auto-start + restart-on-fail:
.\install-mwsqld.ps1
sc.exe start mwsqld
```

On Windows the sealed config must be initialized **as the service account** (or
pre-seeded) before first start, since the daemon account has no login session —
the generated script prints the exact `mwsqlctl ... init` line to run.

The daemon then runs as an account your client user cannot read, so the master
key and sealed config stay out of reach. The reference files and the reasoning
are in `installers/`.

Service mode must use `--file-keystore`: the dedicated daemon account has no
login session, so the OS keyring is unreachable; the master key lives in a
`0700`/ACL-locked state dir instead.

For a non-loopback PostgreSQL bind the daemon refuses cleartext auth unless you
set `MIDDLEWHERE_ALLOW_INSECURE_PG_CLEARTEXT=1`. Use a tunnel instead.

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
`http.check-revoke = false` because Windows schannel cannot reach the
revocation endpoints here, and `AWS_LC_SYS_PREBUILT_NASM = 1` so the crypto
dependency builds without a NASM assembler installed.

## Versioning

One version in `Cargo.toml` covers all three binaries, and `--version` reports
it. Before 1.0, minor versions may break compatibility and patch versions are
fixes only. See [CHANGELOG.md](CHANGELOG.md).

## Good to know

- PostgreSQL prepared statements and parameters work. They are run by inlining
  the parameters and going through the simple-query path, so there are no
  server-side cursors (`maxRows` is ignored, the whole result comes back) and
  no `COPY`.
- MySQL handles normal queries; there are no server-side prepared statements,
  but client-side prepared statements (the Connector/J default) work.
- The local port has no TLS because it is loopback only. Turn SSL off client
  side.
- Read-only is the default and is enforced for every client regardless of what
  the backend account can do.
- A config change needs a daemon restart; the admin tool is offline.
- SSH bastions use password auth today; key auth and auto-reconnect are not
  wired yet.

## License

MIT. See [LICENSE](LICENSE).
