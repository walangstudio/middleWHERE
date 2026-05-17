# middleWHERE

![version](https://img.shields.io/badge/version-0.1.0-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![rust](https://img.shields.io/badge/rust-1.78%2B-orange)
![tests](https://img.shields.io/badge/tests-150%20passing-brightgreen)

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

## Getting started

Pick a state directory. The daemon and the admin tool both point at it. These
examples use `--file-keystore`, which keeps the master key in a locked file in
the state directory; drop it to use the OS keychain instead when you have a
real login session.

```sh
mwsqlctl --state-dir /var/lib/middlewhere --file-keystore init
```

That generates a master key, seals an empty config, and creates the directory
layout. Nothing is exposed in plaintext except the audit log.

### A worked example: staging1, staging2, prod

In this setup the two staging environments share one database login and one
jump host. Production uses a different jump host with its own SSH user and
password, and it logs into the database with the same username as staging but
a different password.

A credential is a backend database user plus its password. Add the one the two
staging environments will share. The password is read from stdin and never
echoed.

```sh
printf '%s' "$STAGING_DB_PASSWORD" | \
  mwsqlctl --state-dir /var/lib/middlewhere --file-keystore \
  cred add app_ro --user app_readonly --password-stdin
```

Add the jump host that both staging environments sit behind. Its host, SSH
user, and password are stored once, here. You can pin its host key so a
swapped jump host is rejected.

```sh
printf '%s' "$STAGING_JUMP_PASSWORD" | \
  mwsqlctl --state-dir /var/lib/middlewhere --file-keystore \
  bastion add staging_jump --host jump.staging.internal --ssh-user tunnel \
  --password-stdin --fingerprint ssh-ed25519:AAAAC3Nz...
```

Create the two staging environments. Both point at the same credential and the
same bastion, so they share that one database login and that one jump host.
Each still gets its own local port and its own client token.

```sh
mwsqlctl --state-dir /var/lib/middlewhere --file-keystore env add staging1 \
  --engine postgres --backend-host db-staging1.internal --database app \
  --credential app_ro --bastion staging_jump --listen-port 6433

mwsqlctl --state-dir /var/lib/middlewhere --file-keystore env add staging2 \
  --engine postgres --backend-host db-staging2.internal --database app \
  --credential app_ro --bastion staging_jump --listen-port 6434
```

Production reaches the database through a different jump host, with a
different SSH user and password from the staging one.

```sh
printf '%s' "$PROD_JUMP_PASSWORD" | \
  mwsqlctl --state-dir /var/lib/middlewhere --file-keystore \
  bastion add prod_jump --host jump.prod.internal --ssh-user prod_tunnel \
  --password-stdin --fingerprint ssh-ed25519:AAAAB3Nz...
```

Production's database login uses the same username as staging,
`app_readonly`, but a different password. Same username, different password is
just a second credential entry with the same `--user` value.

```sh
printf '%s' "$PROD_DB_PASSWORD" | \
  mwsqlctl --state-dir /var/lib/middlewhere --file-keystore \
  cred add prod_ro --user app_readonly --password-stdin

mwsqlctl --state-dir /var/lib/middlewhere --file-keystore env add prod \
  --engine postgres --backend-host db.prod.internal --database app \
  --credential prod_ro --bastion prod_jump --listen-port 6543
```

The same `env add` works for MySQL by passing `--engine mysql`.

### Shared versus own

A credential or a bastion is shared by naming it from more than one
environment. `app_ro` and `staging_jump` are shared because `staging1` and
`staging2` both reference them; rotating that one credential's password
updates both staging environments at once. Production stays separate because
it names its own `prod_ro` and `prod_jump`. Note that `app_ro` and `prod_ro`
both use the database username `app_readonly`: the username being the same
across environments does not make the login shared, only naming the same
credential does.

An environment that omits `--bastion` connects to its backend directly from
the daemon host, with no jump host at all.

### Handing out access

Each environment has a token. Mint one and give it to whoever needs that
environment:

```sh
mwsqlctl --state-dir /var/lib/middlewhere --file-keystore grant staging1
```

That prints the connection line and the token. Rotating it invalidates the old
one. The token is the only thing the caller ever holds.

### Running queries

Start the daemon:

```sh
mwsqld --state-dir /var/lib/middlewhere --file-keystore run
```

Then connect with any client. With `psql`:

```sh
PGPASSWORD=<token> psql -h 127.0.0.1 -p 6433 -U staging1 -d app -c 'SELECT 1'
```

Or with the MySQL wrapper, which remembers the token for you:

```sh
mwsql login staging1 --port 6433
mwsql staging1 -e "SELECT count(*) FROM users"
```

A write attempt comes back as a denied query, not a modified row, and the
attempt is recorded in the audit log.

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

There is no separate installer. `mwsqlctl install-service` prints the platform
file (a systemd unit with `DynamicUser=yes`, a launchd plist, or a Windows
PowerShell script) and the exact privileged steps to apply it. You run that one
step yourself. The daemon then runs as an account your client user cannot read,
so the master key and sealed config stay out of reach. The reference files and
the reasoning are in `installers/`.

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
