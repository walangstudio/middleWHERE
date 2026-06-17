# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com). Dates are
ISO-8601. Semantic versioning; the single workspace version applies to all
three binaries. Pre-1.0: minor versions may carry breaking changes, patch
versions are fixes only.

## [0.3.0] - 2026-06-10

### Added

- **`mwsqlctl init` installs middleWHERE as a managed service in one step.** On
  Linux it self-elevates with `sudo` (elevate-first, so secrets are only ever
  entered in the root process — none crosses the sudo boundary; `current_exe()`
  is absolute, so the binary's extract location is irrelevant), creates the fixed
  `mwsqld` system user, seeds the sealed config, writes a hardened `User=mwsqld`
  unit, and runs `systemctl enable --now`. The daemon starts idle. `init` then
  offers **Configure connections now?** and runs the wizard inline while still
  elevated. `--user` seeds a per-user config (OS keychain, no service, no
  elevation) and leaves configuration to you.
- **`mwsqlctl uninstall` removes a deployment — the inverse of `init`.** Service
  mode self-elevates, stops and deletes the OS service, then wipes the sealed
  config, master key (file keystore or OS keychain entry), and audit log;
  `--user` removes the per-user deployment with no elevation. Destructive and
  irreversible, so it confirms first and refuses to run unattended unless `--yes`
  is given. Idempotent: an already-absent service or state dir is reported, not
  an error.
- **`mwsqlctl wizard` (alias `setup`) configures an already-installed
  deployment.** Guided, masked prompts for bastions / credentials / environments,
  then it restarts the service so the daemon binds the new loopback listeners
  (the daemon reads config once at startup — there is no hot reload). Re-running
  offers add-more / show-current. Requires `init` to have run first.
- A fixed-system-user systemd unit variant (`User=mwsqld` + `ReadWritePaths`)
  alongside the existing `DynamicUser` one. Ownership is stable and inspectable
  with `ls -l`, so "seed as root, then `enable --now`" is predictable — the model
  `init` uses. `install-service` still emits the `DynamicUser` unit.
- `MW_STATE_DIR`, `MW_FILE_KEYSTORE`, and `MW_USER` environment variables back
  the corresponding global flags on `mwsqld` / `mwsqlctl`, so a service operator
  exports them once instead of repeating `--state-dir … --file-keystore`.
- **Connection validation on add.** Adding an environment now opens the bastion
  tunnel (if any) and forces a real connect+auth against the backend, so a wrong
  host / password / unreachable bastion is caught at setup, not at first query.
  The wizard reports the failure and offers keep / edit & retry / discard; the
  scripted `mwsqlctl env add` validates by default, keeps the env, and exits
  non-zero on failure (`--no-validate` skips it). New `mwsqld test --env <name>
  | --all [--json]` does the probe; new `mwsqlctl env test <env> | --all`
  re-checks an existing env. The probe lives in the daemon (which already has the
  SSH + DB stack); `mwsqlctl` shells out to it and stays networking-dependency-free.
- **Paste-ready connection output.** `env add` / `grant` / the wizard now print a
  DBeaver-style field list (host / port / database / user / password / SSL off)
  and a ready-to-use engine URL (`postgresql://…?sslmode=disable`, `mysql://…`)
  alongside the token, so a non-technical operator never has to translate the
  terse one-liner into a client's connection dialog.

### Changed

- **Setup is now two clear steps** — `init` installs the service, `wizard`
  configures it — instead of one all-in-one command, so each step's privileges
  and purpose are obvious. The shared elevation + service-management code lives in
  `mwsqlctl::service`; the elevation re-exec is generalized to forward any
  subcommand.
- **Service-first defaults (reverts the 0.2.2 per-user default).** A flagless
  `mwsqld` / `mwsqlctl` now targets the **system service** dir
  (`/var/lib/middlewhere`, etc.) and the **file** keystore, because the common
  deployment is a managed service. Pass `--user` for the per-user dir + OS
  keychain (the previous default). The shared resolution lives in
  `mw_core::state::resolve_cli_target`.

### Removed

- The `install.sh` / `install.ps1` one-line installers and their unit tests.
  Download the release archive, verify its SHA-256 against `SHA256SUMS`, and
  extract the binaries yourself; `mwsqlctl init` installs the service from
  wherever you put them. This drops the auto-install-into-`~/.local/bin` step
  whose result was not visible to the later `sudo`, which was the original cause
  of the broken service install.

### Fixed

- **`cred add --user` paniced** (clap "could not downcast to bool ... String"):
  the credential's backend-user flag collided with the global `--user`
  deployment flag added this release. Renamed to **`--db-user`**. A
  `Cli::command().debug_assert()` test now guards against this class of arg
  conflict.
- The one-time client token is printed as an **unmissable block** (env name,
  token, port, connection details) by `env add`, `grant`, and the wizard, so it
  can't be scrolled past — previously a single easily-missed line. On Windows the
  Read/inspect commands (`env list`, `cred list`, `grant`, `audit-tail`) and
  service-mode `init` / `wizard` self-elevate via UAC instead of failing against
  the admin-locked state dir.

### Security

- Bumped `tokio-postgres` to 0.7.18 and `postgres-protocol` to 0.6.12 to pick up
  RUSTSEC-2026-0178/0179/0180 — malicious/MITM-server denial-of-service fixes
  (DataRow/hstore decode panics and unbounded SCRAM iteration). middleWHERE only
  connects to operator-configured backends, so exposure is limited, but the
  gateway tunnels to those backends and the fix is free.

## [0.2.2] - 2026-05-29

### Changed

- Interactive `mwsqld` / `mwsqlctl` now default to a **per-user** state dir
  when `--state-dir` is omitted — `~/.local/state/middlewhere` (Linux, honors
  `$XDG_STATE_HOME`), `~/Library/Application Support/middlewhere` (macOS),
  `%LOCALAPPDATA%\middlewhere` (Windows). This matches where the binaries
  install by default and lets `init` / `run` work with no elevation. The
  system dir (`/var/lib/middlewhere`, etc.) is still the default that
  `install-service` bakes into generated service units and that the Windows
  service entrypoint uses; a service deployment overrides with an explicit
  `--state-dir`.
- Installer "Next steps" footer rewritten as init -> configure -> serve, with
  running as a managed service (auto-start) presented alongside a manual run.

## [0.2.1] - 2026-05-29

### Added

- `init` now locks the state directory to `0700` (owner-only) on Unix, so the
  audit log and file names are not readable by other local users. Previously
  only the sealed config and master key were owner-restricted.
- `mwsqlctl init` / `mwsqld init` print a clear, actionable error when the
  default state directory (under `/var/lib`, etc.) cannot be created
  unprivileged: re-run with `sudo`, or pass `--state-dir <a path you own>`.
- `mwsqlctl init` points at `install-service` on success for running as a
  managed service.

### Changed

- Installers (`install.sh` / `install.ps1`) print a "Next steps" footer after a
  successful install, including on the already-installed no-op re-run.

## [0.2.0] - 2026-05-27

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
