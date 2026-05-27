#!/usr/bin/env bash
# Regression guards for the release/CI workflow and build-script findings.
# Pure text assertions over the committed YAML/build.rs so a future edit that
# reintroduces a fixed bug fails here.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="${HERE}/.."
pass=0; fail=0
ok()  { pass=$((pass+1)); printf 'ok   - %s\n' "$1"; }
bad() { fail=$((fail+1)); printf 'FAIL - %s\n' "$1"; }
has()    { if grep -qE "$2" "$1"; then ok "$3"; else bad "$3"; fi; }
hasnot() { if grep -qE "$2" "$1"; then bad "$3"; else ok "$3"; fi; }

REL="${ROOT}/.github/workflows/release.yml"
CI="${ROOT}/.github/workflows/ci.yml"

# Release build must NOT use --locked (the version stamp rewrites Cargo.toml,
# so --locked would abort every release of a tag != the committed lock version).
hasnot "$REL" 'cargo build .*--locked' "release build has no --locked"
has    "$REL" 'cargo build --workspace --release --target' "release build present"

# Duplicate-run guard: dispatch + push-triggered run share a group and cancel.
has "$REL" 'cancel-in-progress: true' "release concurrency cancels in-progress"
has "$REL" 'group: release-' "release concurrency group keyed on tag"

# Checksums target the assets, not the SHA256SUMS file being written.
has    "$REL" 'sha256sum middlewhere-\* > SHA256SUMS' "checksum globs only assets"
hasnot "$REL" 'sha256sum \* > SHA256SUMS' "checksum does not self-include"

# CI (no version stamp) keeps --locked for reproducibility.
has "$CI" 'cargo build --workspace --release --locked --target' "CI build keeps --locked"
has "$CI" 'cargo test --workspace --locked' "CI test keeps --locked"

# Unpatched transitive advisory (rsa via russh) is ignored with a rationale.
has "$CI" 'ignore: RUSTSEC-2023-0071' "cargo audit ignores unpatched rsa advisory"

# Each build.rs hard-fails so a missing resource compiler can't ship a bare PE.
for c in mwsqld mwsqlctl mwsql; do
  b="${ROOT}/crates/${c}/build.rs"
  has "$b" 'res\.compile\(\)' "${c}/build.rs compiles resources"
  has "$b" '\.expect\(' "${c}/build.rs hard-fails on compile error"
  hasnot "$b" 'cargo:warning=winresource: failed' "${c}/build.rs does not swallow failure"
done

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
