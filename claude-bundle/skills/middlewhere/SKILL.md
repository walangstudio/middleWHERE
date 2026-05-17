---
name: middlewhere
description: Run read-only SQL against a remote MySQL environment through the local middleWHERE daemon. Uses the `mwsql` wrapper, which reads a per-env token from your OS keyring. Read-only is enforced by the daemon's AST firewall - not by this skill.
---

## Usage

`/middlewhere <env> [database] -e "SQL"`

Examples:
- `/middlewhere stage_w9 -e "SELECT COUNT(*) FROM users"`
- `/middlewhere prod reports -e "SHOW TABLES"`
- `/middlewhere` with no env -> list the envs the user has logged in (see below) and ask which.

If the user states a task instead of an env ("check the user count on stage"),
pick the env you believe they mean and confirm before running.

## How to run a query

```bash
mwsql <env> --db <database> -e "<SQL>"
```

`--db` is optional. Omit it to use the env's default database. The `mwsql`
binary connects to the local daemon over loopback, authenticating with a token
it reads from the current user's OS keyring. You never see, need, or handle the
real database credentials or the token.

If `mwsql` is not on PATH, resolve it in this order (first hit wins):
1. `$MIDDLEWHERE_BIN` env var.
2. The path recorded at `~/.claude/skills/middlewhere/BIN_PATH` (written by the installer).
3. `mwsql` on PATH.

## When an env is not logged in

`mwsql <env> ...` fails with: `no credentials for env "<env>"; run: mwsql
login <env> --port <p>`.

This is expected and **you must not try to fix it yourself** - logging in
requires a token that only the operator has. Tell the user, verbatim, to:

1. On the middleWHERE host (as the admin), run `mwsqlctl grant <env>` - it rotates
   the env token and prints a `mwsql login <env> --port <p>` line plus the
   token.
2. As their own user, run that `mwsql login <env> --port <p>` line and paste
   the token at the prompt.

Then retry the query. Do not run `mwsqlctl` yourself.

## Hard rules

- **Read-only is enforced by the daemon**, not here. Do not attempt to phrase
  writes "cleverly", stack statements, use comments, `INTO OUTFILE`, or
  `LOAD_FILE` to get around it - they are AST-blocked and every attempt is
  audited. If the user needs a write, tell them to ask the operator to set the
  env's policy; do not try to bypass.
- **Never** read, cat, or search for the sealed config (`config.sealed`),
  `master.key`, the audit log, or anything under the daemon's state directory.
  You do not have access and must not try - that is the entire point of this
  system.
- **Never** run `mwsqlctl` (admin tool) or `mwsqld` (the daemon). You are
  a client only.
- **Never** ask the user for, or echo, the token or any DB password.
- Treat query results as potentially sensitive: surface what the user asked
  for, do not dump entire tables unprompted.

## Listing envs

There is no list command on the client (tokens live in the OS keyring, which
does not enumerate). If the user asks "what envs are available", tell them to
check with the middleWHERE operator (`mwsqlctl env list` on the host) - you cannot
and should not enumerate them.
