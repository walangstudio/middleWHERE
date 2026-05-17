#!/usr/bin/env bash
#
# middleWHERE Claude Code skill installer.
#
# Copies the `middlewhere` skill into ~/.claude/skills/ and records the path of
# the `mwsql` client binary so the skill can find it.
#
# Idempotent: re-running updates the skill files in place.
#
# Usage:
#   ./install.sh                          # install into ~/.claude/skills
#   CLAUDE_SKILLS_DIR=/path ./install.sh  # override skills destination
#   MIDDLEWHERE_BIN=/path/mwsql ./install.sh  # override recorded binary path
#
set -euo pipefail

BUNDLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$BUNDLE_DIR/skills"
TARGET="${CLAUDE_SKILLS_DIR:-$HOME/.claude/skills}"

if [[ ! -d "$SRC" ]]; then
  echo "ERROR: expected bundle at $SRC" >&2
  exit 1
fi

# Resolve the mwsql binary: explicit override, else PATH, else a sibling
# of this bundle's parent (a cargo target dir layout), else give up.
BIN="${MIDDLEWHERE_BIN:-}"
if [[ -z "$BIN" ]] && command -v mwsql &>/dev/null; then
  BIN="$(command -v mwsql)"
fi
if [[ -z "$BIN" ]]; then
  echo "WARNING: 'mwsql' not found on PATH and MIDDLEWHERE_BIN not set." >&2
  echo "         The skill will still install; set MIDDLEWHERE_BIN or add it to PATH." >&2
fi

mkdir -p "$TARGET"
cp -R "$SRC/middlewhere" "$TARGET/"
if [[ -n "$BIN" ]]; then
  echo "$BIN" > "$TARGET/middlewhere/BIN_PATH"
  echo "Recorded mwsql binary: $BIN"
fi
echo "Installed middlewhere skill into $TARGET/middlewhere"
echo "Use it in Claude Code as: /middlewhere <env> -e \"SELECT 1\""
