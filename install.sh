#!/bin/sh
set -e

# middleWHERE installer for Linux and macOS. Downloads the prebuilt binaries
# (mwsqld, mwsqlctl, mwsql) from GitHub Releases, verifies the archive's
# SHA-256, and installs all three. Re-running upgrades in place.
#   curl -fsSL https://raw.githubusercontent.com/walangstudio/middleWHERE/main/install.sh | sh
#   ... | sh -s -- --version v0.2.0      install a specific version
#   ... | sh -s -- --pre-release         install the latest pre-release
#   ... | sh -s -- --uninstall           remove middleWHERE
# On Windows use install.ps1 instead.

REPO="walangstudio/middleWHERE"
BINARIES="mwsqld mwsqlctl mwsql"
VERSION_PROBE="mwsql"   # lightest binary to query --version (no daemon side effects)

if [ -t 1 ]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
  RED='' GREEN='' YELLOW='' CYAN='' BOLD='' RESET=''
fi

info()    { printf "${CYAN}==>${RESET} ${BOLD}%s${RESET}\n" "$1"; }
success() { printf "${GREEN}ok${RESET} %s\n" "$1"; }
warn()    { printf "${YELLOW}warning:${RESET} %s\n" "$1"; }
fatal()   { printf "${RED}error:${RESET} %s\n" "$1" >&2; exit 1; }

TMP_DIR=""
cleanup() { [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ] && rm -rf "$TMP_DIR"; }
trap cleanup EXIT INT TERM

# Map this machine to a Rust release target triple (must match the release assets).
detect_target() {
  case "$(uname -s)" in
    Linux*)  plat="unknown-linux-gnu" ;;
    Darwin*) plat="apple-darwin" ;;
    MINGW*|MSYS*|CYGWIN*)
      fatal "On Windows, use the PowerShell installer: irm https://raw.githubusercontent.com/${REPO}/main/install.ps1 | iex" ;;
    *) fatal "Unsupported OS: $(uname -s)" ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64)  cpu="x86_64" ;;
    aarch64|arm64) cpu="aarch64" ;;
    *) fatal "Unsupported architecture: $(uname -m)" ;;
  esac
  echo "${cpu}-${plat}"
}

http_get() {
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1"
  elif command -v wget >/dev/null 2>&1; then wget -qO- "$1"
  else fatal "curl or wget is required"; fi
}

download() {
  if command -v curl >/dev/null 2>&1; then
    if [ -t 1 ]; then curl -fL --progress-bar "$1" -o "$2"; else curl -fsSL "$1" -o "$2"; fi
  else wget -q "$1" -O "$2"; fi
}

fetch_target_version() {
  use_prerelease="$1"; requested="$2"
  if [ -n "$requested" ]; then
    tag="$requested"; case "$tag" in v*) ;; *) tag="v${tag}" ;; esac
    result="$(http_get "https://api.github.com/repos/${REPO}/releases/tags/${tag}" \
      | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
    [ -n "$result" ] || fatal "Version ${tag} not found"
    echo "$result"
  elif [ "$use_prerelease" = "1" ]; then
    # Split the response into one record per release at each "tag_name" key, so
    # each record holds that release's tag (at its start) and its own
    # "prerelease" flag — independent of how many releases the page lists.
    http_get "https://api.github.com/repos/${REPO}/releases?per_page=100" \
      | awk 'BEGIN { RS="\"tag_name\":" }
             NR > 1 {
               tag=$0; sub(/^[[:space:]]*"/, "", tag); sub(/".*/, "", tag);
               if ($0 ~ /"prerelease":[[:space:]]*true/) { print tag; exit }
             }'
  else
    http_get "https://api.github.com/repos/${REPO}/releases/latest" \
      | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/'
  fi
}

get_installed_version() {
  if command -v "$VERSION_PROBE" >/dev/null 2>&1; then
    ver=$("$VERSION_PROBE" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    [ -n "$ver" ] && echo "v${ver}"
  fi
  # Never let a non-semver probe poison the function's exit status: under
  # `set -e`, a nonzero return here would abort the whole installer.
  return 0
}

verify_checksum() {
  archive="$1"; sums="$2"; name="$(basename "$archive")"
  expected="$(grep " ${name}\$" "$sums" | awk '{print $1}')"
  [ -n "$expected" ] || { warn "No checksum entry for ${name}, skipping verification"; return; }
  if command -v sha256sum >/dev/null 2>&1; then actual="$(sha256sum "$archive" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then actual="$(shasum -a 256 "$archive" | awk '{print $1}')"
  else warn "sha256sum/shasum not found, skipping checksum verification"; return; fi
  [ "$actual" = "$expected" ] || fatal "Checksum mismatch (expected ${expected}, got ${actual})"
  success "Checksum verified"
}

select_install_dir() {
  if [ -w "/usr/local/bin" ]; then echo "/usr/local/bin"
  elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then echo "/usr/local/bin"
  else echo "${HOME}/.local/bin"; fi
}

install_binary() {
  src="$1"; dir="$2"; bin="$(basename "$src")"; dest="${dir}/${bin}"; backup="${dest}.old"
  use_sudo=""; [ -w "$dir" ] || use_sudo="sudo"
  [ -f "$dest" ] && $use_sudo cp "$dest" "$backup"
  if $use_sudo cp "$src" "$dest" && $use_sudo chmod 755 "$dest"; then
    $use_sudo rm -f "$backup"
  else
    [ -f "$backup" ] && { warn "Install of ${bin} failed, restoring previous version..."; $use_sudo mv "$backup" "$dest"; }
    fatal "Installation of ${bin} failed"
  fi
}

check_path() {
  case ":${PATH}:" in
    *":$1:"*) ;;
    *) warn "$1 is not in your PATH"
       printf "  Add to your shell profile (~/.bashrc, ~/.zshrc, ...):\n"
       printf "    ${BOLD}export PATH=\"\$PATH:$1\"${RESET}\n" ;;
  esac
}

uninstall() {
  removed=0
  for bin in $BINARIES; do
    path="$(command -v "$bin" 2>/dev/null || true)"
    [ -n "$path" ] || continue
    info "Removing ${path}..."
    if [ -w "$(dirname "$path")" ]; then rm -f "$path"; else sudo rm -f "$path"; fi
    removed=1
  done
  [ "$removed" = "1" ] && success "middleWHERE uninstalled" || warn "middleWHERE is not installed (no binaries found in PATH)"
}

main() {
  USE_PRERELEASE=0; REQUESTED_VERSION=""; need_version=0
  for arg in "$@"; do
    if [ "$need_version" = "1" ]; then REQUESTED_VERSION="$arg"; need_version=0; continue; fi
    case "$arg" in
      --uninstall)   uninstall; exit 0 ;;
      --pre-release) USE_PRERELEASE=1 ;;
      --version=*)   REQUESTED_VERSION="${arg#--version=}"
                     [ -n "$REQUESTED_VERSION" ] || fatal "--version requires a value (e.g. --version=v0.2.0)" ;;
      --version)     need_version=1 ;;
      *) fatal "Unknown option: $arg" ;;
    esac
  done
  [ "$need_version" = "1" ] && fatal "--version requires a value (e.g. --version v0.2.0)"
  [ "$USE_PRERELEASE" = "1" ] && [ -n "$REQUESTED_VERSION" ] && fatal "--pre-release and --version cannot be combined"

  TARGET="$(detect_target)"

  info "Fetching release info..."
  VERSION="$(fetch_target_version "$USE_PRERELEASE" "$REQUESTED_VERSION")"
  [ -n "$VERSION" ] || fatal "Could not determine target version"

  INSTALLED_VERSION="$(get_installed_version)"
  if [ -n "$INSTALLED_VERSION" ]; then
    if [ "$INSTALLED_VERSION" = "$VERSION" ]; then
      if [ "$USE_PRERELEASE" = "0" ] && [ -z "$REQUESTED_VERSION" ]; then
        success "middleWHERE ${VERSION} is already installed -- nothing to do"; exit 0
      fi
      warn "middleWHERE ${VERSION} is already installed; reinstalling."
    else
      info "Updating middleWHERE ${INSTALLED_VERSION} -> ${VERSION}"
    fi
  else
    info "Installing middleWHERE ${VERSION}"
  fi

  ASSET="middlewhere-${VERSION}-${TARGET}.tar.gz"
  BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
  TMP_DIR="$(mktemp -d)"
  ARCHIVE="${TMP_DIR}/${ASSET}"
  SUMS="${TMP_DIR}/SHA256SUMS"

  info "Downloading ${ASSET}..."
  download "${BASE_URL}/${ASSET}" "$ARCHIVE"
  download "${BASE_URL}/SHA256SUMS" "$SUMS"

  info "Verifying checksum..."
  verify_checksum "$ARCHIVE" "$SUMS"

  info "Extracting..."
  tar -xzf "$ARCHIVE" -C "$TMP_DIR"

  # Validate the whole set before touching the install dir, so a malformed
  # archive can't leave a half-installed, version-skewed toolset.
  for bin in $BINARIES; do
    [ -f "${TMP_DIR}/${bin}" ] || fatal "Binary '${bin}' not found in archive"
  done

  INSTALL_DIR="$(select_install_dir)"
  if [ ! -d "$INSTALL_DIR" ]; then
    if mkdir -p "$INSTALL_DIR" 2>/dev/null; then :
    elif command -v sudo >/dev/null 2>&1; then
      info "Requesting sudo to create ${INSTALL_DIR}"; sudo mkdir -p "$INSTALL_DIR"
    else fatal "Cannot create ${INSTALL_DIR}"; fi
  fi
  info "Installing to ${INSTALL_DIR}..."
  for bin in $BINARIES; do
    install_binary "${TMP_DIR}/${bin}" "$INSTALL_DIR"
  done
  check_path "$INSTALL_DIR"

  if [ -n "$INSTALLED_VERSION" ] && [ "$INSTALLED_VERSION" != "$VERSION" ]; then
    success "middleWHERE updated ${INSTALLED_VERSION} -> ${VERSION}  (mwsqld, mwsqlctl, mwsql)"
  else
    success "middleWHERE ${VERSION} installed successfully  (mwsqld, mwsqlctl, mwsql)"
  fi
  printf "\n"
  command -v "$VERSION_PROBE" >/dev/null 2>&1 && "$VERSION_PROBE" --version || warn "middleWHERE is not in PATH yet. Open a new shell or update your PATH."
}

main "$@"
