# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com). Dates are
ISO-8601. Semantic versioning; the single workspace version applies to all
three binaries. Pre-1.0: minor versions may carry breaking changes, patch
versions are fixes only.

## [0.2.0] - Unreleased

Distribution and supply-chain release. No runtime behaviour changes.

### Added

- One-line installers `install.sh` (Linux/macOS) and `install.ps1` (Windows)
  that download the prebuilt binaries from GitHub Releases, verify the
  archive SHA-256, and install all three (`mwsqld`, `mwsqlctl`, `mwsql`).
- GitHub Actions CI (`fmt` + `clippy` + `cargo audit`, build + test across
  linux/macOS/windows x86_64/arm64) and a tag-driven Release workflow that
  builds all five targets, packages one archive per target, and publishes a
  GitHub Release with `SHA256SUMS`.
- Windows binaries now embed version-info (CompanyName, ProductName,
  FileDescription, version, copyright, OriginalFilename) and an `asInvoker`
  application manifest via a `winresource` build script, which removes the
  "unsigned, zero-metadata native executable" heuristic that triggers AV
  false positives on crypto/network binaries.
- Workspace package metadata (description, repository, homepage, keywords,
  categories, authors) and `cargo binstall --git` support.
- Pinned toolchain (`rust-toolchain.toml`, Rust 1.95.0).
- Unit tests for both installers and the release/build workflow logic
  (`tests/install_sh_test.sh`, `tests/install_ps1_test.ps1`,
  `tests/workflow_test.sh`), run by a CI job. Cover target detection, checksum
  verification (text + binary mode), pre-release selection, atomic
  all-or-nothing multi-binary install with rollback, and PATH handling.

### Security / dependencies

- Bumped `mysql_async` 0.34 → 0.37, which pulls `lru` 0.12 → 0.18 and resolves
  RUSTSEC-2026-0002 (lru `IterMut` unsoundness). No code changes required.
- `cargo audit` ignores RUSTSEC-2023-0071 (rsa "Marvin" timing sidechannel):
  transitive via russh SSH key auth, no patched version exists upstream.
- CI/release: `x86_64-apple-darwin` now builds on `macos-14` (cross-compile +
  Rosetta) instead of the deprecated Intel `macos-13` runner.

### Note

- Release binaries are **not code-signed**. Authenticode/SmartScreen
  reputation accrues over download volume; signing is out of scope for now.

## [0.1.0] - 2026-05-17

Initial release. A security-first SQL gateway that sits between a client
(human, BI tool, JDBC app, or LLM agent) and a real database so the client
runs queries without ever holding the backend credentials, the connection
topology, or write access. Multi-engine (MySQL + PostgreSQL), 150 tests
green, 0 warnings, three release binaries clean. Validated end to end against
live MySQL 9.x and PostgreSQL 16/17 (including Supabase) and against real
DBeaver / JDBC drivers (pgjdbc 42.7, mysql-connector-j 8.4).

### Components

- `mwsqld` - the daemon. Loads the sealed config, serves a per-env loopback
  listener per environment, enforces policy, audits, and runs as a Windows
  service via the SCM.
- `mwsqlctl` - offline admin CLI: init, bastion/credential/env CRUD,
  token rotation, `grant`, policy toggle, audit tail, config import, and
  service-artifact generation.
- `mwsql` - optional client wrapper (MySQL) that keeps the per-env token in
  the user's OS keyring. Any native client also works.
- Crates: `mw-core` (config, AEAD seal, keyring, policy, token, audit, state
  lifecycle) and `mw-net` (wire protocols, engine seam, backend pools,
  router, SSH bastions).

### Engines

- **MySQL / MariaDB** - full. Server-side handshake with
  `mysql_native_password`; automatic `AuthSwitchRequest` so clients that
  default to a non-native plugin (Connector/J -> `caching_sha2_password`)
  connect with no driver flags. Scramble constrained to nonzero printable
  ASCII (real-server behaviour) so NUL-terminated readers don't truncate the
  seed. Server banner advertises 8.4 so version-gated client setup SQL
  targets a modern server. `mysql_async` deadpool backend (5.6-9.x incl.
  `caching_sha2_password`, MariaDB 10/11).
- **PostgreSQL** - full. v3 wire protocol: startup, cleartext-password auth
  termination, Simple Query, and the Extended Query protocol
  (Parse/Bind/Describe/Execute/Sync/Close/Flush). Extended-query execution
  inlines bound parameters into the SQL (string/identifier/comment-aware,
  per-OID text and binary decoding incl. arrays and OID/register types) and
  runs them through the simple-query path so the firewall and audit are
  identical; metadata comes from a real backend Parse+Describe.
  `tokio-postgres` deadpool backend (PG 12-17, incl. Supabase).
- **Engine abstraction.** `Engine`/`Backend` traits with a
  `&'static dyn Engine` registry; the daemon dispatches per env and names no
  concrete engine type.

### Security

- **AST firewall, not regex.** sqlparser-based, parameterised per dialect
  (MySQL + PostgreSQL profiles). A recursive visitor walks the whole
  statement so dangerous functions (`LOAD_FILE`/`sys_exec`/`sys_eval`,
  PG `pg_read_file`/`pg_ls_dir`/`dblink`, `COPY ... PROGRAM`) are denied at any
  depth or clause. `SET` is allowlist-only. Default policy is read-only;
  writes, DDL, and multi-statement are firewalled regardless of client.
- **Sealed config.** All backend credentials, bastion keys, and env
  definitions live in a single ChaCha20-Poly1305 AEAD file with an Argon2id
  KDF. The master key is in the OS secret store, or an ACL/0700-locked
  `master.key` for service mode (a dedicated service identity has no usable
  login session, so the directory-ownership boundary is the protection, an
  equivalent guarantee). Atomic write with one backup; created mode 0600.
- **Per-env token auth.** Env name as username, high-entropy token as
  password; the real backend credentials never leave the daemon. MySQL
  verifies `mysql_native_password` challenge-response; PostgreSQL verifies
  SHA-256(token) over loopback without holding the token. Constant-time
  username compare combined with the constant-time token check via a
  non-short-circuit `&` (no env-name timing oracle). A non-loopback
  PostgreSQL bind refuses cleartext auth unless
  `MIDDLEWHERE_ALLOW_INSECURE_PG_CLEARTEXT=1`.
- **Bastions.** Native SSH tunnels (russh) with pinned host keys; TOFU is
  deny-by-default and never accepted in service mode.
- **Audit.** Every query is logged as JSON lines (decision, statement hash +
  first 64 chars, row count, duration); no secrets.
- Backend errors are not forwarded verbatim; recovered key material is
  zeroized; config import has a path-traversal guard.

### Tooling

- Service installers for systemd (`DynamicUser=yes` + full sandbox), launchd
  (dedicated daemon user), and Windows (virtual service account). A drift
  test pins the checked-in artifacts to the generators.
- `mwsqlctl import` ingests an existing `.env` + `secrets/` deployment into
  a sealed config (bastion/credential/env resolution from the env keys),
  then prints a checklist for retiring the old source.
- A Claude Code skill (`/middlewhere`) for read-only SQL through the `mwsql`
  wrapper, with hard rules that forbid reading the sealed config / master
  key / audit log or running the admin tooling.

### Known limitations

- PostgreSQL extended query is parameter-inlining over the simple-query path:
  no server-side cursors (`maxRows` ignored) and no `COPY`. A raw-backend
  extended-protocol passthrough is the planned long-term design.
- MySQL: only `COM_QUERY`/`COM_PING`/`COM_QUIT`; no server-side prepared
  statements (Connector/J's client-side prepared statements work).
- No TLS on the gateway front (loopback trust boundary), so clients disable SSL.
- Config changes require a daemon restart (online IPC reload deferred).
- russh: password auth only; key auth and keepalive/reconnect deferred.
