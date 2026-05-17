# middleWHERE Claude Code skill

Teaches Claude Code to run read-only SQL through the `mwsql` client
wrapper, which talks to the local middleWHERE daemon over loopback.

## Install

```
./install.sh          # Linux / macOS
.\install.ps1         # Windows
```

This copies `skills/middlewhere/` into `~/.claude/skills/` and records the path
of the `mwsql` binary in `~/.claude/skills/middlewhere/BIN_PATH`.

## What the skill does

- Runs `mwsql <env> [--db <db>] -e "<SQL>"`.
- Surfaces results to the user.

## What it deliberately will not do

- Read the sealed config, master key, or audit log (no access by design).
- Run `mwsqlctl` or `mwsqld`.
- Attempt to bypass the daemon's read-only policy.
- Handle, request, or echo tokens / DB credentials.

## Prerequisite: logging in an env

Tokens are per env, per client user, stored in the OS keyring. One-time
setup, done by a human (not Claude):

1. On the middleWHERE host, the admin runs `mwsqlctl grant <env>`. It rotates
   the env token and prints a `mwsql login <env> --port <p>` line plus the
   token.
2. The client user runs that line and pastes the token at the prompt.

After that, `/middlewhere <env> -e "..."` works until the token is rotated
again.
