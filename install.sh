#!/usr/bin/env bash
set -Eeuo pipefail

# ==========================================
# Simple IPsec Tunnel Installer (Debian/Ubuntu)
# Repo: https://github.com/ach1992/simple-ipsec-tunnel
#
# Installs:
#  - /usr/local/bin/simple-ipsec  (from ipsec_manager.sh)
# Dependencies:
#  - strongswan, iproute2, iputils-ping, curl
# ==========================================

REPO_RAW_BASE="https://raw.githubusercontent.com/ach1992/simple-ipsec-tunnel/main"
SCRIPT_NAME_IN_REPO="ipsec_manager.sh"
INSTALL_PATH="/usr/local/bin/simple-ipsec"
TMP_DIR="/tmp/simple-ipsec-install.$$"

RED="\033[0;31m"; GRN="\033[0;32m"; YEL="\033[0;33m"; BLU="\033[0;34m"; NC="\033[0m"
log()  { echo -e "${BLU}[INFO]${NC} $*"; }
ok()   { echo -e "${GRN}[OK]${NC} $*"; }
warn() { echo -e "${YEL}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*"; }

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    err "Run as root. Example:"
    echo "  curl -fsSL ${REPO_RAW_BASE}/install.sh | sudo bash"
    exit 1
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

install_missing_deps_if_possible() {
  local missing=()
  have_cmd curl  || missing+=("curl")
  have_cmd ip    || missing+=("iproute2")
  have_cmd ping  || missing+=("iputils-ping")
  have_cmd ipsec || missing+=("strongswan")

  if ((${#missing[@]} == 0)); then
    ok "All required dependencies are installed."
    return 0
  fi

  if ! have_cmd apt-get; then
    err "apt-get not found. This installer supports Debian/Ubuntu."
    err "Missing dependencies: ${missing[*]}"
    err "Please install them manually and rerun installer."
    return 1
  fi

  warn "Missing dependencies: ${missing[*]}"
  warn "Attempting install..."

  export DEBIAN_FRONTEND=noninteractive

  # try without update first
  if apt-get install -y "${missing[@]}"; then
    ok "Installed missing dependencies (no apt-get update)."
    return 0
  fi

  warn "Retrying with apt-get update..."
  if apt-get update -y && apt-get install -y "${missing[@]}"; then
    ok "Installed missing dependencies after apt-get update."
    return 0
  fi

  err "Could not install dependencies automatically."
  err "Manual:"
  err "  apt-get update && apt-get install -y ${missing[*]}"
  return 1
}

download_script() {
  mkdir -p "$TMP_DIR"
  log "Downloading ${SCRIPT_NAME_IN_REPO}..."
  curl -fsSL "${REPO_RAW_BASE}/${SCRIPT_NAME_IN_REPO}" -o "${TMP_DIR}/${SCRIPT_NAME_IN_REPO}"
  ok "Downloaded."
}

install_script() {
  log "Installing to ${INSTALL_PATH}..."
  install -m 0755 "${TMP_DIR}/${SCRIPT_NAME_IN_REPO}" "${INSTALL_PATH}"
  ok "Installed."
}

cleanup() { rm -rf "$TMP_DIR" >/dev/null 2>&1 || true; }

main() {
  need_root
  install_missing_deps_if_possible
  download_script
  install_script
  cleanup

  ok "Installed successfully."
  echo
  echo "Run:"
  echo "  sudo simple-ipsec"
}

main "$@"
