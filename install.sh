#!/usr/bin/env bash
set -Eeuo pipefail

# Simple IPsec Tunnel Installer (Debian/Ubuntu)
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

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

ensure_deps() {
  local missing_pkgs=()

  have_cmd curl     || missing_pkgs+=("curl")
  have_cmd ip       || missing_pkgs+=("iproute2")
  have_cmd ping     || missing_pkgs+=("iputils-ping")
  have_cmd timeout  || missing_pkgs+=("coreutils")
  have_cmd iptables || missing_pkgs+=("iptables")
  have_cmd flock   || missing_pkgs+=("util-linux")

  if ! have_cmd ipsec; then
    # Debian 13 (trixie) note:
    # - "strongswan" metapackage focuses on swanctl
    # - for ipsec.conf/starter you typically need strongswan-starter + strongswan-charon (+ strongswan-libcharon which includes socket-default)
    if have_cmd apt-cache && apt-cache show strongswan-charon >/dev/null 2>&1; then
      missing_pkgs+=("strongswan-charon")
    else
      missing_pkgs+=("strongswan")
    fi

    # starter is required for ipsec.conf flows (and is a dependency of strongswan-charon on Debian)
    if have_cmd apt-cache && apt-cache show strongswan-starter >/dev/null 2>&1; then
      missing_pkgs+=("strongswan-starter")
    fi

    # on Debian, socket-default plugin lives in strongswan-libcharon
    if have_cmd apt-cache && apt-cache show strongswan-libcharon >/dev/null 2>&1; then
      missing_pkgs+=("strongswan-libcharon")
    fi
  fi

  if ((${#missing_pkgs[@]} == 0)); then
    ok "All dependencies already installed."
    return 0
  fi

  if ! have_cmd apt-get; then
    err "apt-get not found. This installer supports Debian/Ubuntu."
    err "Missing packages: ${missing_pkgs[*]}"
    exit 1
  fi

  warn "Missing packages: ${missing_pkgs[*]}"
  export DEBIAN_FRONTEND=noninteractive

  log "Installing missing packages (trying without apt-get update first)..."
  if apt-get install -y "${missing_pkgs[@]}"; then
    ok "Installed missing packages."
  else
    warn "Install failed without update. Running apt-get update and retrying..."
    apt-get update -y
    apt-get install -y "${missing_pkgs[@]}"
    ok "Installed missing packages after apt-get update."
  fi

  if ! have_cmd ipsec; then
    err "'ipsec' command still not found after install."
    err "Check paths: /usr/sbin/ipsec or /sbin/ipsec"
    err "PATH: $PATH"
    exit 1
  fi
}

download_script() {
  mkdir -p "$TMP_DIR"

  # If ipsec_manager.sh is present next to this installer, use it (offline/local install)
  local self_dir local_src
  self_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
  local_src="${self_dir}/${SCRIPT_NAME_IN_REPO}"
  if [[ -f "$local_src" ]]; then
    log "Using local ${SCRIPT_NAME_IN_REPO} from: $local_src"
    cp -a "$local_src" "${TMP_DIR}/${SCRIPT_NAME_IN_REPO}"
    ok "Copied locally."
    return 0
  fi

  log "Downloading ${SCRIPT_NAME_IN_REPO}..."
  # retry a few times for flaky networks
  curl -fsSL --retry 5 --retry-delay 1 "${REPO_RAW_BASE}/${SCRIPT_NAME_IN_REPO}" -o "${TMP_DIR}/${SCRIPT_NAME_IN_REPO}"
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
  ensure_deps
  download_script
  install_script
  cleanup

  ok "Installed successfully."
  echo
  echo "Run:"
  echo "  sudo simple-ipsec"
}

main "$@"
