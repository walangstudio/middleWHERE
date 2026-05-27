#!/usr/bin/env bash
# Unit tests for install.sh. Sources the script (MW_INSTALL_NO_MAIN=1 skips the
# entrypoint) and exercises each function with mocked uname/http_get/cp.
# Each finding from code review has a named test below.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="${HERE}/../install.sh"

pass=0; fail=0
ok()   { pass=$((pass+1)); printf 'ok   - %s\n' "$1"; }
bad()  { fail=$((fail+1)); printf 'FAIL - %s\n     %s\n' "$1" "$2"; }
eq()   { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected [$3], got [$2]"; fi; }

export MW_INSTALL_NO_MAIN=1
# shellcheck disable=SC1090
. "$SCRIPT"
set +e   # install.sh enables `set -e`; the harness checks $? itself

# --- detect_target: OS/arch -> Rust triple ---
uname() { case "$1" in -s) printf '%s' "$MOCK_S";; -m) printf '%s' "$MOCK_M";; esac; }
MOCK_S=Linux  MOCK_M=x86_64;  eq "detect_target linux/x86_64"  "$(detect_target)" "x86_64-unknown-linux-gnu"
MOCK_S=Darwin MOCK_M=arm64;   eq "detect_target macos/arm64"   "$(detect_target)" "aarch64-apple-darwin"
MOCK_S=Linux  MOCK_M=aarch64; eq "detect_target linux/arm64"   "$(detect_target)" "aarch64-unknown-linux-gnu"

# --- fetch_target_version: pre-release selection (the awk record-split parser) ---
# newest stable then a pre-release -> picks the pre-release
http_get() { printf '%s' '[{"tag_name":"v0.3.0","prerelease":false},{"tag_name":"v0.3.0-rc.1","prerelease":true},{"tag_name":"v0.2.0","prerelease":false}]'; }
eq "prerelease skips newest stable" "$(fetch_target_version 1 '')" "v0.3.0-rc.1"
# newest is a pre-release
http_get() { printf '%s' '[{"tag_name":"v0.4.0-beta","prerelease":true},{"tag_name":"v0.3.0","prerelease":false}]'; }
eq "prerelease picks newest pre-release" "$(fetch_target_version 1 '')" "v0.4.0-beta"
# no pre-release at all -> empty
http_get() { printf '%s' '[{"tag_name":"v0.3.0","prerelease":false}]'; }
eq "prerelease none -> empty" "$(fetch_target_version 1 '')" ""
# injection: a release body containing the literal text (JSON-escaped) must not spoof selection
http_get() { printf '%s' '[{"tag_name":"v1.0.0","body":"see \"prerelease\":true and \"tag_name\":\"evil\"","prerelease":false}]'; }
eq "prerelease ignores escaped body text" "$(fetch_target_version 1 '')" ""

# --- fetch_target_version: explicit version + latest paths ---
http_get() { printf '%s' '{"tag_name":"v0.2.0"}'; }
eq "requested version resolves tag" "$(fetch_target_version 0 'v0.2.0')" "v0.2.0"
http_get() { printf '%s' '{"tag_name":"v0.9.9"}'; }
eq "latest resolves tag" "$(fetch_target_version 0 '')" "v0.9.9"

# --- verify_checksum: text mode, binary mode, mismatch, multi-entry literal match ---
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
asset="middlewhere-v0.2.0-x86_64-unknown-linux-gnu.tar.gz"
printf 'payload' > "${work}/${asset}"
real="$(sha256sum "${work}/${asset}" | awk '{print $1}')"
# text mode (two spaces) + an unrelated decoy line whose name shares a suffix
printf '%s  decoy-%s\n%s  %s\n' "0000" "$asset" "$real" "$asset" > "${work}/SUMS_text"
( verify_checksum "${work}/${asset}" "${work}/SUMS_text" ) >/dev/null 2>&1
eq "verify_checksum text mode ok" "$?" "0"
# binary mode (space + asterisk)
printf '%s *%s\n' "$real" "$asset" > "${work}/SUMS_bin"
( verify_checksum "${work}/${asset}" "${work}/SUMS_bin" ) >/dev/null 2>&1
eq "verify_checksum binary mode ok" "$?" "0"
# mismatch -> fatal (exit 1)
printf '%s  %s\n' "deadbeef" "$asset" > "${work}/SUMS_bad"
( verify_checksum "${work}/${asset}" "${work}/SUMS_bad" ) >/dev/null 2>&1
eq "verify_checksum mismatch fatals" "$?" "1"
# decoy whose name is a regex-superset must NOT be matched literally
printf '%s  middlewhereXv0X2X0-x86_64-unknown-linux-gnu.tar.gz\n' "feedface" > "${work}/SUMS_decoy"
got="$(awk -v n="$asset" '{ f=$2; sub(/^\*/,"",f); if (f==n) print $1 }' "${work}/SUMS_decoy")"
eq "verify_checksum literal name (no regex-loose match)" "$got" ""

# --- argument parsing: empty --version= must error, not install latest ---
( main "--version=" ) >/dev/null 2>&1; eq "--version= empty errors" "$?" "1"
( main "--version" )  >/dev/null 2>&1; eq "--version no value errors" "$?" "1"
( main "--bogus" )    >/dev/null 2>&1; eq "unknown flag errors" "$?" "1"

# --- install_all: atomic rollback on a mid-set failure (no version skew) ---
src="$(mktemp -d)"; dst="$(mktemp -d)"
for b in $BINARIES; do printf 'NEW-%s' "$b" > "${src}/${b}"; printf 'OLD-%s' "$b" > "${dst}/${b}"; done
# make the copy of the LAST binary (mwsql) fail
cp() { if [ "$1" = "${src}/mwsql" ]; then return 1; fi; command cp "$@"; }
( install_all "$src" "$dst" ) >/dev/null 2>&1
eq "install_all rollback fatals" "$?" "1"
eq "install_all rollback restores mwsqld"  "$(cat "${dst}/mwsqld")"  "OLD-mwsqld"
eq "install_all rollback restores mwsqlctl" "$(cat "${dst}/mwsqlctl")" "OLD-mwsqlctl"
eq "install_all rollback restores mwsql"   "$(cat "${dst}/mwsql")"   "OLD-mwsql"
eq "install_all rollback leaves no .old"   "$(ls "${dst}"/*.old 2>/dev/null | wc -l | tr -d ' ')" "0"
unset -f cp

# --- install_all: success replaces all and cleans backups ---
src2="$(mktemp -d)"; dst2="$(mktemp -d)"
for b in $BINARIES; do printf 'NEW-%s' "$b" > "${src2}/${b}"; printf 'OLD-%s' "$b" > "${dst2}/${b}"; done
( install_all "$src2" "$dst2" ) >/dev/null 2>&1
eq "install_all success exit 0" "$?" "0"
eq "install_all success new content" "$(cat "${dst2}/mwsql")" "NEW-mwsql"
eq "install_all success no .old" "$(ls "${dst2}"/*.old 2>/dev/null | wc -l | tr -d ' ')" "0"

# --- install_all: a failed pre-install backup aborts before any change ---
src3="$(mktemp -d)"; dst3="$(mktemp -d)"
for b in $BINARIES; do printf 'NEW-%s' "$b" > "${src3}/${b}"; printf 'OLD-%s' "$b" > "${dst3}/${b}"; done
cp() { case "$2" in *.old) return 1;; *) command cp "$@";; esac; }
( install_all "$src3" "$dst3" ) >/dev/null 2>&1
eq "install_all backup failure aborts" "$?" "1"
eq "install_all backup failure leaves originals" "$(cat "${dst3}/mwsqld")" "OLD-mwsqld"
unset -f cp

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
