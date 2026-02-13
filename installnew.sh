#!/usr/bin/env bash
set -Eeuo pipefail

# Simple IPsec Tunnel Installer (Debian/Ubuntu)
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Repo info
REPO_OWNER="ach1992"
REPO_NAME="simple-ipsec-tunnel"
REPO_DEFAULT_REF="main"   # online (main branch)
SCRIPT_NAME_IN_REPO="ipsec_manager-new.sh"

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
    echo "  curl -fsSL https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${REPO_DEFAULT_REF}/installnew.sh | sudo bash"
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
  have_cmd flock    || missing_pkgs+=("util-linux")

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

    if have_cmd apt-cache && apt-cache show strongswan-libcharon >/dev/null 2>&1; then
      missing_pkgs+=("strongswan-libcharon")
    fi
  fi

  if ((${#missing_pkgs[@]} == 0)); then
    ok "All dependencies are already installed."
    return 0
  fi

  if ! have_cmd apt-get; then
    err "apt-get not found. This installer supports Debian/Ubuntu only."
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
    err "'ipsec' command still not found after installation."
    err "Check paths: /usr/sbin/ipsec or /sbin/ipsec"
    err "PATH: $PATH"
    exit 1
  fi
}

cleanup() { rm -rf "$TMP_DIR" >/dev/null 2>&1 || true; }

# ---- install mode selection ----
MODE=""  # offline | online | latest

usage() {
  cat <<'EOF'
Usage:
  sudo bash installnew.sh [--offline | --online | --latest-release]

Options:
  --offline         Install using local files (no download from GitHub)
  --online          Download from main branch (default)
  --latest-release  Download from the latest GitHub release tag
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --offline) MODE="offline"; shift ;;
      --online) MODE="online"; shift ;;
      --latest-release|--latest|--newest) MODE="latest"; shift ;;
      -h|--help) usage; exit 0 ;;
      *)
        warn "Unknown argument: $1"
        usage
        exit 1
        ;;
    esac
  done
}

is_tty() { [[ -t 0 ]] && [[ -t 1 ]]; }

prompt_mode() {
  # If already set by args, keep it
  [[ -n "$MODE" ]] && return 0

  # Non-interactive: default to online
  if ! is_tty; then
    MODE="online"
    return 0
  fi

  echo
  echo "Select installation mode:"
  echo "  1) Offline (use local project files)"
  echo "  2) Online (download from main branch)"
  echo "  3) Online (download latest release / newest version)"
  echo
  read -r -p "Enter choice [1-3] (default 2): " choice
  choice="${choice:-2}"

  case "$choice" in
    1) MODE="offline" ;;
    2) MODE="online" ;;
    3) MODE="latest" ;;
    *) warn "Invalid choice; defaulting to Online (main)."; MODE="online" ;;
  esac
}

# ---- offline/local discovery ----
find_local_script() {
  local candidates=()
  local self_dir pwd_dir

  self_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
  pwd_dir="$(pwd -P)"

  # Priority order:
  candidates+=("${self_dir}/${SCRIPT_NAME_IN_REPO}")
  candidates+=("${pwd_dir}/${SCRIPT_NAME_IN_REPO}")

  # Common locations if user placed files under /root
  candidates+=("/root/${SCRIPT_NAME_IN_REPO}")
  candidates+=("/root/${REPO_NAME}/${SCRIPT_NAME_IN_REPO}")

  # Other common locations
  candidates+=("/opt/${REPO_NAME}/${SCRIPT_NAME_IN_REPO}")

  local c
  for c in "${candidates[@]}"; do
    if [[ -f "$c" ]]; then
      echo "$c"
      return 0
    fi
  done

  return 1
}

# ---- online download helpers ----
repo_raw_base_for_ref() {
  local ref="$1"
  echo "https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${ref}"
}

get_latest_release_tag() {
  # GitHub API (no auth). Parse tag_name without jq.
  # If rate-limited or fails, fallback to main.
  local api="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest"
  local tag
  tag="$(curl -fsSL "$api" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*/\1/p' | head -n1 || true)"
  if [[ -z "$tag" ]]; then
    return 1
  fi
  echo "$tag"
}

download_script_offline() {
  mkdir -p "$TMP_DIR"

  local local_src
  if local_src="$(find_local_script)"; then
    log "Offline mode: using local file: $local_src"
    cp -a "$local_src" "${TMP_DIR}/${SCRIPT_NAME_IN_REPO}"
    ok "Copied local script."
    return 0
  fi

  err "Offline mode selected, but ${SCRIPT_NAME_IN_REPO} was not found."
  err "Checked: script directory, current directory, /root, and common locations."
  err "Fix: place ${SCRIPT_NAME_IN_REPO} next to installnew.sh, or in /root."
  exit 1
}

download_script_online_main() {
  mkdir -p "$TMP_DIR"
  local base; base="$(repo_raw_base_for_ref "$REPO_DEFAULT_REF")"

  log "Downloading ${SCRIPT_NAME_IN_REPO} from: ${base}/..."
  curl -fsSL --retry 5 --retry-delay 1 "${base}/${SCRIPT_NAME_IN_REPO}" -o "${TMP_DIR}/${SCRIPT_NAME_IN_REPO}"
  ok "Downloaded script."
}

download_script_online_latest_release() {
  mkdir -p "$TMP_DIR"

  log "Detecting latest release tag..."
  local tag
  if ! tag="$(get_latest_release_tag)"; then
    warn "Could not detect latest release (maybe rate-limited). Falling back to main."
    download_script_online_main
    return 0
  fi

  local base; base="$(repo_raw_base_for_ref "$tag")"
  log "Downloading ${SCRIPT_NAME_IN_REPO} from latest release tag: ${tag}"
  curl -fsSL --retry 5 --retry-delay 1 "${base}/${SCRIPT_NAME_IN_REPO}" -o "${TMP_DIR}/${SCRIPT_NAME_IN_REPO}"
  ok "Downloaded script (latest release)."
}

download_script() {
  case "$MODE" in
    offline) download_script_offline ;;
    online)  download_script_online_main ;;
    latest)  download_script_online_latest_release ;;
    *)
      warn "Unknown MODE=$MODE; defaulting to online."
      MODE="online"
      download_script_online_main
      ;;
  esac
}

install_script() {
  log "Installing to ${INSTALL_PATH}..."
  install -m 0755 "${TMP_DIR}/${SCRIPT_NAME_IN_REPO}" "${INSTALL_PATH}"
  ok "Installed."
}

main() {
  parse_args "$@"
  need_root
  prompt_mode

  log "Selected installation mode: ${MODE}"
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
