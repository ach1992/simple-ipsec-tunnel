#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================================
#  Simple IPsec Tunnel (IKEv2 + VTI) - Multi Tunnel Manager
#  Optimized for Debian/Ubuntu (multiple versions)
# ============================================================

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
APP_NAME="Simple IPsec Tunnel"
REPO_URL="https://github.com/ach1992/simple-ipsec-tunnel"

APP_DIR="/etc/simple-ipsec"
TUNNELS_DIR="$APP_DIR/tunnels.d"
SYSCTL_FILE="$APP_DIR/99-simple-ipsec.conf"

IPSEC_INCLUDE_DIR="/etc/ipsec.d/simple-ipsec"
IPSEC_CONF="/etc/ipsec.conf"
IPSEC_SECRETS="/etc/ipsec.secrets"
SECRETS_FILE="/etc/ipsec.d/simple-ipsec.secrets"

SERVICE_TEMPLATE="/etc/systemd/system/simple-ipsec@.service"
UP_HELPER="/usr/local/sbin/simple-ipsec-up"
DOWN_HELPER="/usr/local/sbin/simple-ipsec-down"

MONITOR_HELPER="/usr/local/sbin/simple-ipsec-monitor"
MONITOR_SERVICE="/etc/systemd/system/simple-ipsec-monitor.service"
MONITOR_TIMER="/etc/systemd/system/simple-ipsec-monitor.timer"

# Defaults
TUN_NAME_DEFAULT="vti0"
MTU_DEFAULT="1385"
MARK_MIN=10
MARK_MAX=999999
TABLE_DEFAULT="220"
ENABLE_FORWARDING_DEFAULT="yes"
DISABLE_RPFILTER_DEFAULT="yes"
ENABLE_SRC_VALID_MARK_DEFAULT="yes"
ENABLE_DISABLE_POLICY_DEFAULT="no"   # risky globally; per-iface only

# Timeouts (slow/unstable networks may need more time)
SYSTEMCTL_RESTART_TIMEOUT="${SYSTEMCTL_RESTART_TIMEOUT:-180}"   # seconds
IPSEC_UP_TIMEOUT="${IPSEC_UP_TIMEOUT:-60}"                     # seconds
XFRM_WAIT_MAX="${XFRM_WAIT_MAX:-90}"                           # seconds

# Colors
RED="\033[0;31m"; GRN="\033[0;32m"; YEL="\033[0;33m"; BLU="\033[0;34m"
MAG="\033[0;35m"; CYA="\033[0;36m"; WHT="\033[1;37m"; NC="\033[0m"

log()   { echo -e "${BLU}[INFO]${NC} $*"; }
ok()    { echo -e "${GRN}[OK]${NC} $*"; }
warn()  { echo -e "${YEL}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*"; }

pause() { read -r -p "Press Enter to continue..." _ || true; }

# -----------------------
# Global lock to avoid races between create/delete/restart
# -----------------------
with_lock() {
  local lock="/run/simple-ipsec.lock"
  mkdir -p /run 2>/dev/null || true
  exec 9>"$lock"
  flock -x 9
  "$@"
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    err "Run as root."
    exit 1
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

require_cmds() {
  local missing=()
  for c in ip awk sed grep sysctl systemctl ping timeout flock; do
    have_cmd "$c" || missing+=("$c")
  done
  have_cmd ipsec || missing+=("strongswan (ipsec)")
  have_cmd iptables || missing+=("iptables")
  if ((${#missing[@]})); then
    err "Missing required commands: ${missing[*]}"
    err "Debian/Ubuntu install:"
    err "  apt-get update && apt-get install -y strongswan iproute2 iputils-ping iptables"
    exit 1
  fi
}

ensure_dirs() {
  mkdir -p "$APP_DIR" "$TUNNELS_DIR" "$IPSEC_INCLUDE_DIR"
  chmod 700 "$APP_DIR" "$TUNNELS_DIR" "$IPSEC_INCLUDE_DIR" || true
  touch "$SECRETS_FILE"
  chmod 600 "$SECRETS_FILE" || true
}

ensure_strongswan_service_running() {
  # On some images strongSwan is installed but the daemon is not started/enabled yet.
  # If charon/starter is down, "ipsec up" will fail and the tunnel will never come up.
  if ! have_cmd systemctl; then
    return 0
  fi

  if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx 'strongswan-starter.service'; then
    systemctl enable --now strongswan-starter.service >/dev/null 2>&1 || true
  elif systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx 'strongswan.service'; then
    systemctl enable --now strongswan.service >/dev/null 2>&1 || true
  fi
}

# -----------------------
# Validation helpers
# -----------------------
is_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local IFS=.
  read -r a b c d <<<"$ip"
  for o in "$a" "$b" "$c" "$d"; do
    [[ "$o" =~ ^[0-9]+$ ]] || return 1
    (( o >= 0 && o <= 255 )) || return 1
  done
  return 0
}

is_ifname() {
  local n="$1"
  [[ "$n" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]] || return 1
  return 0
}

is_mark() {
  local m="$1"
  [[ "$m" =~ ^[0-9]+$ ]] && return 0
  [[ "$m" =~ ^0x[0-9a-fA-F]+$ ]] && return 0
  return 1
}

mark_to_dec() {
  local m="$1"
  if [[ "$m" =~ ^0x ]]; then
    echo $((16#${m#0x}))
  else
    echo "$m"
  fi
}

# Stable preference to avoid duplicate ip rules
rule_pref_for() {
  local mark_dec
  mark_dec="$(mark_to_dec "$1")"

  # Use a stable UNIQUE preference derived from MARK to avoid collisions across multiple tunnels.
  # Keep it above the built-in local rule (0) but below main/default (32766/32767) for readability.
  if (( mark_dec < 10000 )); then
    echo $((10000 + mark_dec))
  else
    echo "$mark_dec"
  fi
}

default_iface() { ip route 2>/dev/null | awk '/^default/{print $5; exit}'; }

get_iface_ip() {
  local iface="$1"
  ip -4 -o addr show dev "$iface" 2>/dev/null | awk '{print $4}' | head -n1 | cut -d/ -f1
}

# -----------------------
# Paths / naming
# -----------------------
conf_path_for() { echo "$TUNNELS_DIR/${1}.conf"; }
conn_name_for() { echo "simple-ipsec-${1}"; }
ipsec_conn_conf_for() { echo "$IPSEC_INCLUDE_DIR/${1}.conf"; }
service_for() { echo "simple-ipsec@${1}.service"; }

# -----------------------
# Tunnel list / choose
# -----------------------
list_tunnels() {
  shopt -s nullglob
  for f in "$TUNNELS_DIR"/*.conf; do basename "$f" .conf; done
  shopt -u nullglob
}

choose_tunnel() {
  mapfile -t tunnels < <(list_tunnels)
  ((${#tunnels[@]})) || { err "No tunnels found."; return 1; }

  echo -e "${MAG}Available tunnels:${NC}"
  local i
  for i in "${!tunnels[@]}"; do printf "  %s) %s\n" "$((i+1))" "${tunnels[$i]}"; done

  local choice
  while true; do
    read -r -p "Select tunnel [1-${#tunnels[@]}] (Enter=cancel): " choice || true
    [[ -n "${choice:-}" ]] || return 1
    if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice>=1 && choice<=${#tunnels[@]} )); then
      SELECTED_TUN="${tunnels[$((choice-1))]}"
      return 0
    fi
    err "Invalid selection."
  done
}

# -----------------------
# Read/Write per tunnel conf
# -----------------------
read_conf() {
  local f; f="$(conf_path_for "$1")"
  [[ -f "$f" ]] || return 1
  # shellcheck disable=SC1090
  source "$f"
}

write_conf() {
  local tun="$1"
  local f; f="$(conf_path_for "$tun")"
  local pref; pref="$(rule_pref_for "$MARK" "$TABLE")"

  cat >"$f" <<EOF
# Generated by simple-ipsec
ROLE="${ROLE}"
PAIR_CODE="${PAIR_CODE}"
TUN_NAME="${TUN_NAME}"
LOCAL_WAN_IP="${LOCAL_WAN_IP}"
REMOTE_WAN_IP="${REMOTE_WAN_IP}"
TUN_LOCAL_CIDR="${TUN_LOCAL_CIDR}"
TUN_REMOTE_IP="${TUN_REMOTE_IP}"
MARK="${MARK}"
TABLE="${TABLE}"
RULE_PREF="${pref}"
MTU="${MTU}"
ENABLE_FORWARDING="${ENABLE_FORWARDING}"
DISABLE_RPFILTER="${DISABLE_RPFILTER}"
ENABLE_SRC_VALID_MARK="${ENABLE_SRC_VALID_MARK}"
ENABLE_DISABLE_POLICY="${ENABLE_DISABLE_POLICY}"
PSK="${PSK}"
EOF
  chmod 600 "$f" || true
}

# -----------------------
# Name handling (auto vtiN)
# -----------------------
name_taken_anywhere() {
  local name="$1"
  [[ -f "$(conf_path_for "$name")" ]] && return 0
  ip link show "$name" >/dev/null 2>&1 && return 0
  return 1
}

find_first_free_vti_name() {
  local base="${1:-vti}" i=0 cand
  while true; do
    cand="${base}${i}"
    if ! name_taken_anywhere "$cand"; then echo "$cand"; return 0; fi
    i=$((i+1))
    (( i <= 4096 )) || return 1
  done
}

# -----------------------
# PAIR CODE -> /30
# -----------------------
generate_pair_code() { echo "10.$(( (RANDOM%254)+1 )).$(( (RANDOM%254)+1 ))"; }

parse_pair_code() {
  local pc="$1"
  [[ "$pc" =~ ^10\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  local x="${BASH_REMATCH[1]}" y="${BASH_REMATCH[2]}"
  (( x>=0 && x<=255 && y>=0 && y<=255 )) || return 1
  echo "$x $y"
}

recompute_tunnel_ips_from_pair() {
  local parsed rx ry
  parsed="$(parse_pair_code "$PAIR_CODE")" || { err "PAIR_CODE invalid."; return 1; }
  rx="${parsed% *}"; ry="${parsed#* }"

  if [[ "$ROLE" == "source" ]]; then
    TUN_LOCAL_CIDR="10.${rx}.${ry}.1/30"
    TUN_REMOTE_IP="10.${rx}.${ry}.2"
  else
    TUN_LOCAL_CIDR="10.${rx}.${ry}.2/30"
    TUN_REMOTE_IP="10.${rx}.${ry}.1"
  fi
}

# -----------------------
# COPY BLOCK
# -----------------------
print_copy_block() {
  local src dst
  if [[ "$ROLE" == "source" ]]; then src="$LOCAL_WAN_IP"; dst="$REMOTE_WAN_IP"
  else src="$REMOTE_WAN_IP"; dst="$LOCAL_WAN_IP"
  fi

  echo "----- SIMPLE_IPSEC_COPY_BLOCK -----"
  echo "PAIR_CODE=${PAIR_CODE}"
  echo "SOURCE_PUBLIC_IP=${src}"
  echo "DEST_PUBLIC_IP=${dst}"
  echo "TUN_NAME=${TUN_NAME}"
  echo "MARK=${MARK}"
  echo "TABLE=${TABLE}"
  echo "MTU=${MTU}"
  echo "ENABLE_FORWARDING=${ENABLE_FORWARDING}"
  echo "DISABLE_RPFILTER=${DISABLE_RPFILTER}"
  echo "ENABLE_SRC_VALID_MARK=${ENABLE_SRC_VALID_MARK}"
  echo "ENABLE_DISABLE_POLICY=${ENABLE_DISABLE_POLICY}"
  echo "PSK=${PSK}"
  echo "----- END_COPY_BLOCK -----"
}

prompt_paste_copy_block() {
  echo -e "${CYA}Optional:${NC} Paste COPY BLOCK now (press Enter to skip)."
  echo -e "Finish paste by pressing ${WHT}Enter TWICE${NC} on empty lines."
  echo

  local first=""
  read -r -p "Paste the COPY BLOCK (or just Enter to skip): " first || true
  [[ -n "${first:-}" ]] || return 0

  local lines=("$first") empty_count=0 line
  while true; do
    line=""
    read -r line || true
    if [[ -z "${line:-}" ]]; then
      empty_count=$((empty_count+1))
      if (( empty_count == 1 )); then
        # requested UX: show message after first Enter
        echo -e "${MAG}Please press Enter one more time to finish.${NC}"
        continue
      fi
      # second empty line => finish silently (no "Paste finished..." message)
      break
    fi
    empty_count=0
    lines+=("$line")
  done

  local kv key val
  for kv in "${lines[@]}"; do
    [[ "$kv" =~ ^[A-Z0-9_]+= ]] || continue
    key="${kv%%=*}"; val="${kv#*=}"
    case "$key" in
      PAIR_CODE) PAIR_CODE="$val" ;;
      SOURCE_PUBLIC_IP) PASTE_SOURCE_PUBLIC_IP="$val" ;;
      DEST_PUBLIC_IP)   PASTE_DEST_PUBLIC_IP="$val" ;;
      TUN_NAME) TUN_NAME="$val" ;;
      MARK) MARK="$val" ;;
      TABLE) TABLE="$val" ;;
      MTU) MTU="$val" ;;
      ENABLE_FORWARDING) ENABLE_FORWARDING="$val" ;;
      DISABLE_RPFILTER)  DISABLE_RPFILTER="$val" ;;
      ENABLE_SRC_VALID_MARK) ENABLE_SRC_VALID_MARK="$val" ;;
      ENABLE_DISABLE_POLICY) ENABLE_DISABLE_POLICY="$val" ;;
      PSK) PSK="$val" ;;
      *) : ;;
    esac
  done

  [[ -z "${PAIR_CODE:-}" ]] || parse_pair_code "$PAIR_CODE" >/dev/null || { err "Bad PAIR_CODE in COPY BLOCK."; return 1; }
  [[ -z "${PASTE_SOURCE_PUBLIC_IP:-}" ]] || is_ipv4 "$PASTE_SOURCE_PUBLIC_IP" || { err "Bad SOURCE_PUBLIC_IP in COPY BLOCK."; return 1; }
  [[ -z "${PASTE_DEST_PUBLIC_IP:-}" ]] || is_ipv4 "$PASTE_DEST_PUBLIC_IP" || { err "Bad DEST_PUBLIC_IP in COPY BLOCK."; return 1; }
  [[ -z "${TUN_NAME:-}" ]] || is_ifname "$TUN_NAME" || { err "Bad TUN_NAME in COPY BLOCK."; return 1; }
  [[ -z "${MARK:-}" ]] || is_mark "$MARK" || { err "Bad MARK in COPY BLOCK."; return 1; }
  [[ -z "${TABLE:-}" ]] || [[ "$TABLE" =~ ^[0-9]+$ ]] || { err "Bad TABLE in COPY BLOCK."; return 1; }
  [[ -z "${MTU:-}" ]] || [[ "$MTU" =~ ^[0-9]+$ ]] || { err "Bad MTU in COPY BLOCK."; return 1; }

  ok "COPY BLOCK parsed."
  return 0
}

# -----------------------
# Secrets (multi-safe)
# -----------------------
secrets_marker_begin() { echo "# BEGIN simple-ipsec:${1}"; }
secrets_marker_end()   { echo "# END simple-ipsec:${1}"; }

remove_secrets_block() {
  local tun="$1"
  [[ -f "$SECRETS_FILE" ]] || return 0
  sed -i "\|^# BEGIN simple-ipsec:${tun}\$|,\|^# END simple-ipsec:${tun}\$|d" "$SECRETS_FILE" || true
}

write_ipsec_secrets_block() {
  local tun="$1"
  remove_secrets_block "$tun"

  local begin end
  begin="$(secrets_marker_begin "$tun")"
  end="$(secrets_marker_end "$tun")"

  # NOTE (multi-tunnel safe):
  # If you create multiple tunnels between the same public IP pair, IP-based PSK lines become ambiguous.
  # We therefore use unique IDs derived from PAIR_CODE so each tunnel can have its own PSK safely.
  local id_source id_dest
  id_source="@simple-ipsec-${PAIR_CODE}-source"
  id_dest="@simple-ipsec-${PAIR_CODE}-destination"

  {
    echo "$begin"
    echo "# Peer pair: ${LOCAL_WAN_IP} <-> ${REMOTE_WAN_IP}"
    echo "# IDs: ${id_source} <-> ${id_dest}"
    echo "${id_source} ${id_dest} : PSK \"${PSK}\""
    echo "${id_dest} ${id_source} : PSK \"${PSK}\""
    echo "$end"
  } >> "$SECRETS_FILE"

  chmod 600 "$SECRETS_FILE" || true
}

# -----------------------
# strongSwan include hooks
# -----------------------
ensure_strongswan_includes() {
  if [[ ! -f "$IPSEC_CONF" ]]; then err "$IPSEC_CONF not found. strongSwan installed?"; return 1; fi
  if ! grep -qE '^\s*include\s+/etc/ipsec\.d/simple-ipsec/\*\.conf\s*$' "$IPSEC_CONF"; then
    warn "Adding include line to $IPSEC_CONF (backup will be created)"
    cp -a "$IPSEC_CONF" "${IPSEC_CONF}.bak.$(date +%s)" || true
    printf "\n# added by simple-ipsec\ninclude /etc/ipsec.d/simple-ipsec/*.conf\n" >> "$IPSEC_CONF"
  fi

  if [[ ! -f "$IPSEC_SECRETS" ]]; then err "$IPSEC_SECRETS not found."; return 1; fi
  if ! grep -qE '^\s*include\s+/etc/ipsec\.d/simple-ipsec\.secrets\s*$' "$IPSEC_SECRETS"; then
    warn "Adding include line to $IPSEC_SECRETS (backup will be created)"
    cp -a "$IPSEC_SECRETS" "${IPSEC_SECRETS}.bak.$(date +%s)" || true
    printf "\n# added by simple-ipsec\ninclude /etc/ipsec.d/simple-ipsec.secrets\n" >> "$IPSEC_SECRETS"
  fi

  touch "$SECRETS_FILE"
  chmod 600 "$SECRETS_FILE" || true
}

write_ipsec_conn_conf() {
  local tun="$1"
  local conn_name; conn_name="$(conn_name_for "$tun")"

  # Unique tunnel IDs (PAIR_CODE-based) so multiple tunnels between the same public IPs can coexist safely.
  local id_source id_dest left_id right_id
  id_source="@simple-ipsec-${PAIR_CODE}-source"
  id_dest="@simple-ipsec-${PAIR_CODE}-destination"
  if [[ "${ROLE}" == "source" ]]; then
    left_id="$id_source"
    right_id="$id_dest"
  else
    left_id="$id_dest"
    right_id="$id_source"
  fi

  # Unique traffic selectors per tunnel to avoid CHILD_SA duplicates when running multiple tunnels
  # between the same WAN IP pair.
  local left_ts right_ts
  left_ts="${TUN_LOCAL_CIDR%%/*}/32"
  right_ts="${TUN_REMOTE_IP}/32"

  cat >"$(ipsec_conn_conf_for "$tun")" <<EOF
# generated by simple-ipsec
conn ${conn_name}
  keyexchange=ikev2
  type=tunnel
  auto=start
  authby=psk

  left=${LOCAL_WAN_IP}
  right=${REMOTE_WAN_IP}

  # Multi-tunnel safe identities (do NOT rely on IP-based PSK lookups)
  leftid=${left_id}
  rightid=${right_id}

  # Route-based (policy routing via mark)
  mark=${MARK}/0xffffffff
  installpolicy=no
  forceencaps=yes

  # Unique selectors (prevents duplicate CHILD_SA across multiple tunnels)
  leftsubnet=${left_ts}
  rightsubnet=${right_ts}

  ## Crypto proposals (modern + compatible)
  ike=aes256gcm16-sha256-modp2048,aes256-sha256-modp2048
  esp=aes256gcm16-sha256,aes256-sha256

  # Dead Peer Detection (stability on unstable networks)
  dpdaction=restart
  dpddelay=30s
  dpdtimeout=120s
  keyingtries=%forever
EOF

  chmod 600 "$(ipsec_conn_conf_for "$tun")" || true
}

# -----------------------
# Sysctl persist (global)
# -----------------------
compute_global_forwarding_needed() {
  local t
  while IFS= read -r t; do
    read_conf "$t" || continue
    [[ "${ENABLE_FORWARDING:-no}" == "yes" ]] && { echo "yes"; return; }
  done < <(list_tunnels)
  echo "no"
}
compute_rpfilter_needed() {
  local t
  while IFS= read -r t; do
    read_conf "$t" || continue
    [[ "${DISABLE_RPFILTER:-no}" == "yes" ]] && { echo "yes"; return; }
  done < <(list_tunnels)
  echo "no"
}
compute_src_valid_mark_needed() {
  local t
  while IFS= read -r t; do
    read_conf "$t" || continue
    [[ "${ENABLE_SRC_VALID_MARK:-no}" == "yes" ]] && { echo "yes"; return; }
  done < <(list_tunnels)
  echo "no"
}
compute_disable_policy_needed() {
  local t
  while IFS= read -r t; do
    read_conf "$t" || continue
    [[ "${ENABLE_DISABLE_POLICY:-no}" == "yes" ]] && { echo "yes"; return; }
  done < <(list_tunnels)
  echo "no"
}

write_sysctl_persist() {
  local forwarding_needed rp_needed svm_needed dp_needed
  forwarding_needed="$(compute_global_forwarding_needed)"
  rp_needed="$(compute_rpfilter_needed)"
  svm_needed="$(compute_src_valid_mark_needed)"
  dp_needed="$(compute_disable_policy_needed)"

  {
    echo "# Simple IPsec Tunnel sysctl (persist) - generated"
    echo "net.ipv4.ip_forward=$( [[ "$forwarding_needed" == "yes" ]] && echo 1 || echo 0 )"

    echo "net.ipv4.conf.all.accept_redirects=0"
    echo "net.ipv4.conf.default.accept_redirects=0"
    echo "net.ipv4.conf.all.send_redirects=0"
    echo "net.ipv4.conf.default.send_redirects=0"

    if [[ "$svm_needed" == "yes" ]]; then
      echo "net.ipv4.conf.all.src_valid_mark=1"
    fi

    if [[ "$rp_needed" == "yes" ]]; then
      echo "net.ipv4.conf.all.rp_filter=0"
      echo "net.ipv4.conf.default.rp_filter=0"
    fi

    # do not set all.disable_policy=1 globally
    local t
    while IFS= read -r t; do
      [[ -n "$t" ]] || continue
      if [[ "$rp_needed" == "yes" ]]; then
        echo "net.ipv4.conf.${t}.rp_filter=0"
      fi
      if [[ "$dp_needed" == "yes" ]]; then
        echo "net.ipv4.conf.${t}.disable_policy=1"
      fi
      echo "net.ipv4.conf.${t}.accept_redirects=0"
      echo "net.ipv4.conf.${t}.send_redirects=0"
    done < <(list_tunnels)
  } >"$SYSCTL_FILE"

  chmod 644 "$SYSCTL_FILE" || true

  # Make sysctl persistent in the standard sysctl.d path too.
  # This avoids "works until reboot" issues.
  local sysctl_d="/etc/sysctl.d/99-simple-ipsec.conf"
  ln -sf "$SYSCTL_FILE" "$sysctl_d" >/dev/null 2>&1 || true

  # Apply immediately (explicitly load our file; sysctl --system ignores /etc/simple-ipsec/ by default)
  sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || true
}

# -----------------------
# systemd template + helpers
# -----------------------
ensure_systemd_template() {
  cat >"$SERVICE_TEMPLATE" <<'EOF'
[Unit]
Description=Simple IPsec Tunnel - IPsec VTI (%i)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes

TimeoutStartSec=180
TimeoutStopSec=30

ExecStart=/usr/local/sbin/simple-ipsec-up %i
ExecStop=/usr/local/sbin/simple-ipsec-down %i

[Install]
WantedBy=multi-user.target
EOF

  # -----------------------
  # UP helper
  # -----------------------
  cat >"$UP_HELPER" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

# Fast + deterministic startup (multi-tunnel safe):
# - Create VTI
# - Start IPsec (tolerate "already up" / duplicates as long as XFRM state for THIS MARK exists)
# - Install XFRM policies for tunnel endpoint ping (scoped by MARK + reqid)
# - Optionally add minimal policy-routing scaffolding (safe defaults)

IPSEC_UP_TIMEOUT="${IPSEC_UP_TIMEOUT:-12}"          # seconds per try
IPSEC_UP_TRIES="${IPSEC_UP_TRIES:-2}"              # retries
WAIT_LOCAL_IP_MAX="${WAIT_LOCAL_IP_MAX:-15}"        # seconds
XFRM_STATE_WAIT="${XFRM_STATE_WAIT:-8}"             # seconds

APP_DIR="/etc/simple-ipsec"
TUNNELS_DIR="$APP_DIR/tunnels.d"
SYSCTL_FILE="$APP_DIR/99-simple-ipsec.conf"

tun="${1:-}"
[[ -n "${tun}" ]] || { echo "Usage: simple-ipsec-up <tunnel_name>" >&2; exit 2; }

CONF_FILE="$TUNNELS_DIR/${tun}.conf"
[[ -f "$CONF_FILE" ]] || { echo "Config not found: $CONF_FILE" >&2; exit 1; }
# shellcheck disable=SC1090
source "$CONF_FILE"

conn_name="simple-ipsec-${tun}"

log()  { echo "[simple-ipsec-up:${tun}] $*"; }
warn() { echo "[simple-ipsec-up:${tun}][WARN] $*" >&2; }
err()  { echo "[simple-ipsec-up:${tun}][ERROR] $*" >&2; }

mark_to_dec() {
  local m="$1"
  if [[ "$m" =~ ^0x ]]; then echo $((16#${m#0x})); else echo "$m"; fi
}
mark_dec() { mark_to_dec "${MARK}"; }
mark_hex() { printf "0x%08x" "$(mark_dec)"; }

local_tun_ip() { echo "${TUN_LOCAL_CIDR%%/*}"; }

ensure_kernel_modules() {
  modprobe ip_vti >/dev/null 2>&1 || true
  modprobe xfrm_user >/dev/null 2>&1 || true
}

detect_strongswan_unit() {
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl cat strongswan-starter.service >/dev/null 2>&1; then
      echo "strongswan-starter.service"; return 0
    fi
    if systemctl cat strongswan.service >/dev/null 2>&1; then
      echo "strongswan.service"; return 0
    fi
  fi
  echo ""
}

ensure_strongswan_running_and_healthy() {
  local unit
  unit="$(detect_strongswan_unit)"

  if [[ -n "$unit" ]]; then
    systemctl start "$unit" >/dev/null 2>&1 || true
  fi

  if ! timeout 5 ipsec statusall >/dev/null 2>&1; then
    err "strongSwan seems not healthy (ipsec statusall failed)."
    if [[ -n "$unit" ]]; then
      warn "systemd status: $unit"
      systemctl --no-pager --full status "$unit" || true
      if command -v journalctl >/dev/null 2>&1; then
        echo
        warn "Recent strongSwan logs:"
        journalctl -u "$unit" -n 120 --no-pager || true
      fi
    else
      warn "Could not detect strongSwan systemd unit (strongswan-starter/strongswan)."
    fi
    exit 1
  fi
}

wait_for_local_ip() {
  local i
  for i in $(seq 1 "${WAIT_LOCAL_IP_MAX}"); do
    if ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -qx "${LOCAL_WAN_IP}"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

apply_sysctl() {
  [[ -f "$SYSCTL_FILE" ]] && sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || true

  [[ "${ENABLE_FORWARDING:-no}" == "yes" ]] && sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

  if [[ "${ENABLE_SRC_VALID_MARK:-no}" == "yes" ]]; then
    sysctl -w net.ipv4.conf.all.src_valid_mark=1 >/dev/null 2>&1 || true
  fi

  if [[ "${DISABLE_RPFILTER:-no}" == "yes" ]]; then
    sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null 2>&1 || true
    sysctl -w "net.ipv4.conf.${TUN_NAME}.rp_filter=0" >/dev/null 2>&1 || true
  fi

  if [[ "${ENABLE_DISABLE_POLICY:-no}" == "yes" ]]; then
    sysctl -w "net.ipv4.conf.${TUN_NAME}.disable_policy=1" >/dev/null 2>&1 || true
  fi
}

ensure_firewall_rules() {
  log "Ensuring firewall rules for IPsec..."

  iptables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
      iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  iptables -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
      iptables -I FORWARD 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  iptables -C INPUT -p udp --dport 500 -j ACCEPT 2>/dev/null || iptables -I INPUT 2 -p udp --dport 500 -j ACCEPT
  iptables -C INPUT -p udp --dport 4500 -j ACCEPT 2>/dev/null || iptables -I INPUT 3 -p udp --dport 4500 -j ACCEPT
  iptables -C INPUT -p esp -j ACCEPT 2>/dev/null || iptables -I INPUT 4 -p esp -j ACCEPT

  iptables -C FORWARD -i "${TUN_NAME}" -j ACCEPT 2>/dev/null || iptables -I FORWARD 2 -i "${TUN_NAME}" -j ACCEPT
  iptables -C FORWARD -o "${TUN_NAME}" -j ACCEPT 2>/dev/null || iptables -I FORWARD 3 -o "${TUN_NAME}" -j ACCEPT
}

ensure_vti() {
  local key_dec
  key_dec="$(mark_dec)"

  # Recreate every time to avoid stale endpoints/keys after edits
  if ip link show "${TUN_NAME}" >/dev/null 2>&1; then
    ip link set "${TUN_NAME}" down >/dev/null 2>&1 || true
    ip link del "${TUN_NAME}" >/dev/null 2>&1 || true
  fi

  ip link add "${TUN_NAME}" type vti local "${LOCAL_WAN_IP}" remote "${REMOTE_WAN_IP}" key "${key_dec}"
  ip link set "${TUN_NAME}" mtu "${MTU}" >/dev/null 2>&1 || true
  ip addr flush dev "${TUN_NAME}" >/dev/null 2>&1 || true
  ip addr add "${TUN_LOCAL_CIDR}" dev "${TUN_NAME}"
  ip link set "${TUN_NAME}" up
}

ensure_tunnel_routes() {
  # Minimal + safe scaffolding:
  # - Ensure we have an ip rule for this MARK to lookup TABLE
  # - Ensure the connected /30 exists in that TABLE (does NOT change default routes)
  local md subnet
  md="$(mark_dec)"
  subnet="$(echo "${TUN_LOCAL_CIDR%/*}" | awk -F. '{print $1"."$2"."$3".0/30"}')"

  # rule preference must exist; if not present in conf (older installs), derive from MARK
  if [[ -z "${RULE_PREF:-}" ]]; then
    RULE_PREF="$md"
    (( RULE_PREF < 10000 )) && RULE_PREF=$((10000 + RULE_PREF))
  fi

  # Add rule if missing
  if ! ip -4 rule show 2>/dev/null | awk -v p="${RULE_PREF}" -v m="${md}" -v t="${TABLE}" '
      $1==(p":") && $0~("fwmark "m) && $0~(" lookup "t) {found=1}
      END{exit(found?0:1)}
    '; then
    ip -4 rule add pref "${RULE_PREF}" fwmark "${md}/0xffffffff" lookup "${TABLE}" 2>/dev/null || true
  fi

  # Ensure the connected subnet exists in the table (idempotent)
  ip -4 route replace table "${TABLE}" "${subnet}" dev "${TUN_NAME}" src "$(local_tun_ip)" 2>/dev/null || true
  ip route flush cache >/dev/null 2>&1 || true
}

ensure_mangle_mark_rules() {
  # Minimal marking rules (safe):
  # - Mark packets towards remote tunnel IP so they consistently use the correct policy routing if needed
  # - Mark packets arriving from the VTI to keep reply routing consistent
  iptables -t mangle -C OUTPUT -d "${TUN_REMOTE_IP}/32" -j MARK --set-xmark "${MARK}/0xffffffff" 2>/dev/null || \
    iptables -t mangle -A OUTPUT -d "${TUN_REMOTE_IP}/32" -j MARK --set-xmark "${MARK}/0xffffffff"

  iptables -t mangle -C PREROUTING -i "${TUN_NAME}" -j MARK --set-xmark "${MARK}/0xffffffff" 2>/dev/null || \
    iptables -t mangle -A PREROUTING -i "${TUN_NAME}" -j MARK --set-xmark "${MARK}/0xffffffff"
}

# -------- XFRM helpers (multi-tunnel safe: filter by MARK) --------
xfrm_state_present() {
  local mh
  mh="$(mark_hex)"
  ip xfrm state 2>/dev/null | awk -v m="${mh}" -v a="${LOCAL_WAN_IP}" -v b="${REMOTE_WAN_IP}" '
    function flush() {
      if (want && mark==m) { found=1 }
    }
    $1=="src" && $3=="dst" {
      flush()
      src=$2; dst=$4; mark=""
      want = ((src==a && dst==b) || (src==b && dst==a)) ? 1 : 0
      next
    }
    $1=="mark" {
      mark=$2; sub(/\/.*/, "", mark)
      next
    }
    END { flush(); exit(found?0:1) }
  '
}

wait_for_xfrm_state() {
  local i
  for i in $(seq 1 "${XFRM_STATE_WAIT}"); do
    xfrm_state_present && return 0
    sleep 1
  done
  return 1
}

xfrm_reqid_from_state() {
  local mh
  mh="$(mark_hex)"
  ip xfrm state 2>/dev/null | awk -v m="${mh}" -v a="${LOCAL_WAN_IP}" -v b="${REMOTE_WAN_IP}" '
    function flush() {
      if (want && mark==m && reqid!="") { print reqid; exit }
    }
    $1=="src" && $3=="dst" {
      flush()
      src=$2; dst=$4; mark=""; reqid=""
      want = ((src==a && dst==b) || (src==b && dst==a)) ? 1 : 0
      next
    }
    want && $1=="proto" && $2=="esp" {
      for(i=1;i<=NF;i++) if($i=="reqid") { reqid=$(i+1) }
      gsub(/[^0-9]/,"",reqid)
      next
    }
    want && $1=="mark" {
      mark=$2; sub(/\/.*/, "", mark)
      next
    }
    END { flush() }
  ' | head -n1
}

xfrm_policy_install_tunnel_ips() {
  local lip rip reqid md
  lip="$(local_tun_ip)"
  rip="${TUN_REMOTE_IP}"
  md="$(mark_dec)"

  reqid="$(xfrm_reqid_from_state || true)"
  [[ -n "${reqid:-}" ]] || reqid="1"

  # best-effort delete old policies (with and without mark)
  ip xfrm policy delete src "${lip}/32" dst "${rip}/32" dir out mark "${md}" mask 0xffffffff 2>/dev/null || true
  ip xfrm policy delete src "${rip}/32" dst "${lip}/32" dir in  mark "${md}" mask 0xffffffff 2>/dev/null || true
  ip xfrm policy delete src "${lip}/32" dst "${rip}/32" dir fwd mark "${md}" mask 0xffffffff 2>/dev/null || true
  ip xfrm policy delete src "${lip}/32" dst "${rip}/32" dir out 2>/dev/null || true
  ip xfrm policy delete src "${rip}/32" dst "${lip}/32" dir in  2>/dev/null || true
  ip xfrm policy delete src "${lip}/32" dst "${rip}/32" dir fwd 2>/dev/null || true

  # add policies for tunnel endpoint IPs (ping will work deterministically)
  ip xfrm policy add src "${lip}/32" dst "${rip}/32" dir out \
    mark "${md}" mask 0xffffffff \
    tmpl src "${LOCAL_WAN_IP}"  dst "${REMOTE_WAN_IP}" proto esp reqid "${reqid}" mode tunnel 2>/dev/null || true

  ip xfrm policy add src "${rip}/32" dst "${lip}/32" dir in \
    mark "${md}" mask 0xffffffff \
    tmpl src "${REMOTE_WAN_IP}" dst "${LOCAL_WAN_IP}" proto esp reqid "${reqid}" mode tunnel 2>/dev/null || true

  ip xfrm policy add src "${lip}/32" dst "${rip}/32" dir fwd \
    mark "${md}" mask 0xffffffff \
    tmpl src "${LOCAL_WAN_IP}"  dst "${REMOTE_WAN_IP}" proto esp reqid "${reqid}" mode tunnel 2>/dev/null || true
}

start_ipsec_or_fail() {
  ipsec rereadsecrets >/dev/null 2>&1 || true
  ipsec reload >/dev/null 2>&1 || true

  local i
  for i in $(seq 1 "${IPSEC_UP_TRIES}"); do
    log "Bringing up IPsec: ${conn_name} (try ${i}/${IPSEC_UP_TRIES})..."
    if timeout "${IPSEC_UP_TIMEOUT}" ipsec up "${conn_name}"; then
      return 0
    fi

    # Multi-tunnel safe tolerance:
    # If IPsec says "failed" but the XFRM state for THIS tunnel MARK exists, consider it up.
    if xfrm_state_present; then
      warn "ipsec up reported failure, but XFRM state for mark=$(mark_hex) is present. Continuing."
      return 0
    fi

    warn "ipsec up failed (try ${i})."
    sleep 1
  done

  err "IPsec did not come up."
  echo
  warn "ipsec statusall (top):"
  timeout 8 ipsec statusall | sed -n '1,140p' || true
  exit 1
}

ensure_kernel_modules
apply_sysctl
ensure_firewall_rules

if ! wait_for_local_ip; then
  err "Local public IP not present yet: ${LOCAL_WAN_IP} (network not ready)."
  err "Try later: systemctl restart simple-ipsec@${tun}.service"
  exit 1
fi

ensure_vti
ensure_tunnel_routes
ensure_mangle_mark_rules
ensure_strongswan_running_and_healthy
start_ipsec_or_fail

if ! wait_for_xfrm_state; then
  err "No XFRM state found for mark=$(mark_hex) after IPsec up. Tunnel is not established."
  echo
  warn "ip xfrm state (filtered):"
  ip xfrm state 2>/dev/null | grep -n "mark $(mark_hex)" || true
  echo
  warn "ipsec statusall (top):"
  timeout 8 ipsec statusall | sed -n '1,140p' || true
  exit 1
fi

xfrm_policy_install_tunnel_ips
log "Tunnel is up (XFRM state present for mark=$(mark_hex))."
EOF

  # -----------------------
  # DOWN helper
  # -----------------------
  cat >"$DOWN_HELPER" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="/etc/simple-ipsec"
TUNNELS_DIR="$APP_DIR/tunnels.d"

tun="${1:-}"
[[ -n "${tun}" ]] || { echo "Usage: simple-ipsec-down <tunnel_name>" >&2; exit 2; }

CONF_FILE="$TUNNELS_DIR/${tun}.conf"
[[ -f "$CONF_FILE" ]] || exit 0
# shellcheck disable=SC1090
source "$CONF_FILE"

conn_name="simple-ipsec-${tun}"

mark_to_dec() {
  local m="$1"
  if [[ "$m" =~ ^0x ]]; then echo $((16#${m#0x})); else echo "$m"; fi
}
mark_dec() { mark_to_dec "${MARK}"; }

local_tun_ip() { echo "${TUN_LOCAL_CIDR%%/*}"; }

cleanup_firewall_rules() {
  local other_tunnel_count
  other_tunnel_count=$(find "$TUNNELS_DIR" -maxdepth 1 -name "*.conf" -not -name "${tun}.conf" 2>/dev/null | wc -l)

  if [[ "$other_tunnel_count" -eq 0 ]]; then
    iptables -D INPUT -p esp -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -p udp --dport 4500 -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -p udp --dport 500 -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
  fi

  iptables -D FORWARD -i "${TUN_NAME}" -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -o "${TUN_NAME}" -j ACCEPT 2>/dev/null || true
}

cleanup_iptables_mangle_rules() {
  iptables -t mangle -D OUTPUT -d "${TUN_REMOTE_IP}/32" -j MARK --set-xmark "${MARK}/0xffffffff" 2>/dev/null || true
  iptables -t mangle -D PREROUTING -i "${TUN_NAME}" -j MARK --set-xmark "${MARK}/0xffffffff" 2>/dev/null || true
}

cleanup_xfrm_policies() {
  local lip rip md
  lip="$(local_tun_ip)"
  rip="${TUN_REMOTE_IP}"
  md="$(mark_dec)"

  ip xfrm policy delete src "${lip}/32" dst "${rip}/32" dir out mark "${md}" mask 0xffffffff 2>/dev/null || true
  ip xfrm policy delete src "${rip}/32" dst "${lip}/32" dir in  mark "${md}" mask 0xffffffff 2>/dev/null || true
  ip xfrm policy delete src "${lip}/32" dst "${rip}/32" dir fwd mark "${md}" mask 0xffffffff 2>/dev/null || true

  ip xfrm policy delete src "${lip}/32" dst "${rip}/32" dir out 2>/dev/null || true
  ip xfrm policy delete src "${rip}/32" dst "${lip}/32" dir in  2>/dev/null || true
  ip xfrm policy delete src "${lip}/32" dst "${rip}/32" dir fwd 2>/dev/null || true
}

cleanup_policy_routing() {
  local subnet md

  md="$(mark_dec)"
  subnet="$(echo "${TUN_LOCAL_CIDR%/*}" | awk -F. '{print $1"."$2"."$3".0/30"}')"

  # Remove ip rule (best-effort)
  if [[ -n "${RULE_PREF:-}" ]]; then
    ip -4 rule del pref "${RULE_PREF}" 2>/dev/null || true
  fi

  # Also delete any matching rule by fwmark/table (in case pref changed)
  if [[ -n "${TABLE:-}" ]]; then
    ip -4 rule show 2>/dev/null | awk -v m="$md" -v t="${TABLE}" '
      $0 ~ ("fwmark " m) && $0 ~ (" lookup " t) {print $1}
    ' | sed 's/://' | while read -r pref; do
      ip -4 rule del pref "$pref" 2>/dev/null || true
    done

    # Remove route in the policy table
    ip -4 route del table "${TABLE}" "${subnet}" dev "${TUN_NAME}" 2>/dev/null || true
  fi

  ip route flush cache >/dev/null 2>&1 || true
}

ipsec down "${conn_name}" >/dev/null 2>&1 || true

cleanup_firewall_rules
cleanup_xfrm_policies
cleanup_policy_routing
cleanup_iptables_mangle_rules

ip link set "${TUN_NAME}" down >/dev/null 2>&1 || true
ip link del "${TUN_NAME}" >/dev/null 2>&1 || true
EOF

  # -----------------------
  # FIX helper (force XFRM policy repair)
  # -----------------------
  FIX_HELPER="/usr/local/sbin/simple-ipsec-fix"
  cat >"$FIX_HELPER" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

IPSEC_UP_TIMEOUT="${IPSEC_UP_TIMEOUT:-12}"
IPSEC_UP_TRIES="${IPSEC_UP_TRIES:-2}"
XFRM_STATE_WAIT="${XFRM_STATE_WAIT:-8}"

APP_DIR="/etc/simple-ipsec"
TUNNELS_DIR="$APP_DIR/tunnels.d"

tun="${1:-}"
[[ -n "${tun}" ]] || { echo "Usage: simple-ipsec-fix <tunnel_name>" >&2; exit 2; }

CONF_FILE="$TUNNELS_DIR/${tun}.conf"
[[ -f "$CONF_FILE" ]] || { echo "Config not found: $CONF_FILE" >&2; exit 1; }
# shellcheck disable=SC1090
source "$CONF_FILE"

conn_name="simple-ipsec-${tun}"

# --- UI helpers ---
BOLD="[1m"; DIM="[2m"; GRN="[0;32m"; RED="[0;31m"; YEL="[0;33m"; CYA="[0;36m"; NC="[0m"
ok()   { echo -e "  ${GRN}✔${NC} $*"; }
bad()  { echo -e "  ${RED}✖${NC} $*"; }
info() { echo -e "  ${CYA}•${NC} $*"; }
warn() { echo -e "  ${YEL}!${NC} $*"; }

mark_to_dec() {
  local m="$1"
  if [[ "$m" =~ ^0x ]]; then echo $((16#${m#0x})); else echo "$m"; fi
}
mark_dec() { mark_to_dec "${MARK}"; }
mark_hex() { printf "0x%08x" "$(mark_dec)"; }
local_tun_ip() { echo "${TUN_LOCAL_CIDR%%/*}"; }

print_header() {
  echo -e "${BOLD}============================================================${NC}"
  echo -e "${BOLD} Force fix policies${NC}  ${DIM}(no logic change, cleaner output)${NC}"
  echo -e "${BOLD}------------------------------------------------------------${NC}"
  echo -e "${BOLD} Tunnel:${NC} ${tun}"
  echo -e "${BOLD} Public:${NC} ${LOCAL_WAN_IP}  <->  ${REMOTE_WAN_IP}"
  echo -e "${BOLD} VTI:${NC}    ${TUN_NAME}   ${DIM}${TUN_LOCAL_CIDR} -> ${TUN_REMOTE_IP}${NC}"
  echo -e "${BOLD} MARK/TABLE:${NC} ${MARK} / ${TABLE}   ${DIM}(mark_hex=$(mark_hex))${NC}"
  echo -e "${BOLD}============================================================${NC}"
}

# -------- XFRM helpers (multi-tunnel safe: filter by MARK) --------
xfrm_state_present() {
  local mh
  mh="$(mark_hex)"
  ip xfrm state 2>/dev/null | awk -v m="${mh}" -v a="${LOCAL_WAN_IP}" -v b="${REMOTE_WAN_IP}" '
    function flush() {
      if (want && mark==m) { found=1 }
    }
    $1=="src" && $3=="dst" {
      flush()
      src=$2; dst=$4; mark=""
      want = ((src==a && dst==b) || (src==b && dst==a)) ? 1 : 0
      next
    }
    $1=="mark" { mark=$2; sub(/\/.*/, "", mark); next }
    END { flush(); exit(found?0:1) }
  '
}

wait_for_xfrm_state() {
  local i
  for i in $(seq 1 "${XFRM_STATE_WAIT}"); do
    xfrm_state_present && return 0
    sleep 1
  done
  return 1
}

xfrm_reqid_from_state() {
  local mh
  mh="$(mark_hex)"
  ip xfrm state 2>/dev/null | awk -v m="${mh}" -v a="${LOCAL_WAN_IP}" -v b="${REMOTE_WAN_IP}" '
    function flush() {
      if (want && mark==m && reqid!="") { print reqid; exit }
    }
    $1=="src" && $3=="dst" {
      flush()
      src=$2; dst=$4; mark=""; reqid=""
      want = ((src==a && dst==b) || (src==b && dst==a)) ? 1 : 0
      next
    }
    want && $1=="proto" && $2=="esp" {
      for(i=1;i<=NF;i++) if($i=="reqid") { reqid=$(i+1) }
      gsub(/[^0-9]/,"",reqid)
      next
    }
    want && $1=="mark" { mark=$2; sub(/\/.*/, "", mark); next }
    END { flush() }
  ' | head -n1
}

xfrm_policy_install_tunnel_ips() {
  local lip rip reqid md
  lip="$(local_tun_ip)"
  rip="${TUN_REMOTE_IP}"
  md="$(mark_dec)"

  reqid="$(xfrm_reqid_from_state || true)"
  [[ -n "${reqid:-}" ]] || reqid="1"

  # Delete old (best-effort)
  ip xfrm policy delete src "${lip}/32" dst "${rip}/32" dir out mark "${md}" mask 0xffffffff 2>/dev/null || true
  ip xfrm policy delete src "${rip}/32" dst "${lip}/32" dir in  mark "${md}" mask 0xffffffff 2>/dev/null || true
  ip xfrm policy delete src "${lip}/32" dst "${rip}/32" dir fwd mark "${md}" mask 0xffffffff 2>/dev/null || true
  ip xfrm policy delete src "${lip}/32" dst "${rip}/32" dir out 2>/dev/null || true
  ip xfrm policy delete src "${rip}/32" dst "${lip}/32" dir in  2>/dev/null || true
  ip xfrm policy delete src "${lip}/32" dst "${rip}/32" dir fwd 2>/dev/null || true

  # Add policies for tunnel endpoints
  ip xfrm policy add src "${lip}/32" dst "${rip}/32" dir out \
    mark "${md}" mask 0xffffffff \
    tmpl src "${LOCAL_WAN_IP}"  dst "${REMOTE_WAN_IP}" proto esp reqid "${reqid}" mode tunnel 2>/dev/null || true

  ip xfrm policy add src "${rip}/32" dst "${lip}/32" dir in \
    mark "${md}" mask 0xffffffff \
    tmpl src "${REMOTE_WAN_IP}" dst "${LOCAL_WAN_IP}" proto esp reqid "${reqid}" mode tunnel 2>/dev/null || true

  ip xfrm policy add src "${lip}/32" dst "${rip}/32" dir fwd \
    mark "${md}" mask 0xffffffff \
    tmpl src "${LOCAL_WAN_IP}"  dst "${REMOTE_WAN_IP}" proto esp reqid "${reqid}" mode tunnel 2>/dev/null || true
}

start_ipsec_or_fail() {
  ipsec rereadsecrets >/dev/null 2>&1 || true
  ipsec reload >/dev/null 2>&1 || true

  local i out rc
  for i in $(seq 1 "${IPSEC_UP_TRIES}"); do
    rc=0
    info "IPsec up: ${conn_name} (try ${i}/${IPSEC_UP_TRIES})"
    out="$(timeout "${IPSEC_UP_TIMEOUT}" ipsec up "${conn_name}" 2>&1)" || rc=$?

    # If command succeeded, make it quiet unless user wants logs
    if [[ "$rc" -eq 0 ]]; then
      ok "IPsec command returned success."
      return 0
    fi

    # Tolerate duplicate/already-up if the correct XFRM state exists
    if xfrm_state_present; then
      warn "ipsec up returned non-zero, but XFRM state for mark=$(mark_hex) exists. Continuing."
      return 0
    fi

    warn "ipsec up failed (rc=${rc})."
    echo -e "${DIM}${out}${NC}" | tail -n 20 || true
    sleep 1
  done

  bad "IPsec did not come up."
  timeout 8 ipsec statusall | sed -n '1,160p' || true
  exit 1
}

print_header

# Step 1) Ensure IPsec is up (or already up)
start_ipsec_or_fail

# Step 2) Ensure XFRM state for THIS tunnel exists
info "Checking XFRM state..."
if wait_for_xfrm_state; then
  ok "XFRM state: present (mark=$(mark_hex))"
else
  bad "XFRM state: missing (mark=$(mark_hex))"
  ip xfrm state 2>/dev/null | sed -n '1,120p' || true
  exit 1
fi

# Step 3) Re-install ping policies (same logic as before)
info "Installing XFRM ping policies for tunnel endpoints..."
xfrm_policy_install_tunnel_ips
ok "Policies installed."

# Step 4) Show relevant policies (clean output)
echo
echo -e "${BOLD}Policies (filtered):${NC}"
ip xfrm policy 2>/dev/null | awk -v a="$(local_tun_ip)" -v b="${TUN_REMOTE_IP}" '
  $1=="src" && ($2 ~ a || $4 ~ b || $2 ~ b || $4 ~ a) {print}
' || true

# Step 5) Ping test
echo
info "Ping test: ${TUN_REMOTE_IP}"
if ping -c 3 -W 2 "${TUN_REMOTE_IP}" >/dev/null 2>&1; then
  ok "Ping: OK"
else
  bad "Ping: FAIL"
  warn "Hint: check SA counters: ip -s xfrm state"
fi

echo -e "${BOLD}------------------------------------------------------------${NC}"
echo -e "${BOLD}Done.${NC}"
EOF

  chmod +x "$UP_HELPER" "$DOWN_HELPER" "$FIX_HELPER" || true
  systemctl daemon-reload
}

ensure_monitor_units() {
  # System-wide health-check + auto-repair.
  # Runs as a systemd timer and NEVER interferes with create/edit/remove because it uses the same lock file.

  cat >"$MONITOR_HELPER" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="/etc/simple-ipsec"
TUNNELS_DIR="$APP_DIR/tunnels.d"
LOCK="/run/simple-ipsec.lock"

log() { echo "[simple-ipsec-monitor] $*"; }

mkdir -p /run >/dev/null 2>&1 || true
exec 9>"$LOCK"
# Do NOT block: if manager is editing tunnels, just exit quietly.
if ! flock -n 9; then
  exit 0
fi

shopt -s nullglob
confs=("$TUNNELS_DIR"/*.conf)
shopt -u nullglob
((${#confs[@]})) || exit 0

mark_to_dec() {
  local m="$1"
  if [[ "$m" =~ ^0x ]]; then echo $((16#${m#0x})); else echo "$m"; fi
}
mark_hex_from_mark() {
  local md
  md="$(mark_to_dec "$1")"
  printf "0x%08x" "$md"
}

xfrm_present_for() {
  local mark="$1" a="$2" b="$3"
  local mh
  mh="$(mark_hex_from_mark "$mark")"
  ip xfrm state 2>/dev/null | awk -v m="${mh}" -v a="${a}" -v b="${b}" '
    function flush() {
      if (want && mark==m) { found=1 }
    }
    $1=="src" && $3=="dst" {
      flush()
      src=$2; dst=$4; mark=""
      want = ((src==a && dst==b) || (src==b && dst==a)) ? 1 : 0
      next
    }
    $1=="mark" { mark=$2; sub(/\/.*/, "", mark); next }
    END { flush(); exit(found?0:1) }
  '
}

for conf in "${confs[@]}"; do
  tun="$(basename "$conf" .conf)"

  # shellcheck disable=SC1090
  source "$conf"

  svc="simple-ipsec@${tun}.service"

  service_active=0
  systemctl is-active --quiet "$svc" && service_active=1

  iface_present=0
  ip link show "${TUN_NAME}" >/dev/null 2>&1 && iface_present=1

  xfrm_state=0
  xfrm_present_for "${MARK}" "${LOCAL_WAN_IP}" "${REMOTE_WAN_IP}" && xfrm_state=1

  ping_ok=0
  ping -c 1 -W 1 "${TUN_REMOTE_IP}" >/dev/null 2>&1 && ping_ok=1

  # Healthy?
  if (( service_active && iface_present && xfrm_state && ping_ok )); then
    continue
  fi

  # If the service/interface/state is not ready, try (re)starting the service.
  if (( !service_active || !iface_present || !xfrm_state )); then
    log "[${tun}] unhealthy -> service=${service_active} iface=${iface_present} xfrm=${xfrm_state} ping=${ping_ok} :: start service"
    systemctl reset-failed "$svc" >/dev/null 2>&1 || true
    systemctl start --no-block "$svc" >/dev/null 2>&1 || systemctl restart --no-block "$svc" >/dev/null 2>&1 || true
    continue
  fi

  # Otherwise: service is up + interface exists + XFRM present, but ping failed -> repair policies.
  log "[${tun}] ping failed -> repairing policies"
  if [[ -x /usr/local/sbin/simple-ipsec-fix ]]; then
    /usr/local/sbin/simple-ipsec-fix "$tun" >/dev/null 2>&1 || true
  else
    systemctl restart --no-block "$svc" >/dev/null 2>&1 || true
  fi
done
EOF

  chmod +x "$MONITOR_HELPER" || true

  cat >"$MONITOR_SERVICE" <<'EOF'
[Unit]
Description=Simple IPsec Monitor (healthcheck + auto-repair)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/simple-ipsec-monitor
EOF

  cat >"$MONITOR_TIMER" <<'EOF'
[Unit]
Description=Run Simple IPsec Monitor periodically

[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
AccuracySec=5s
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now simple-ipsec-monitor.timer >/dev/null 2>&1 || true
}

enable_service() {
  local svc; svc="$(service_for "$1")"
  # Enable should be fast; avoid blocking the CLI by NOT using --now for oneshot units.
  systemctl enable "$svc" >/dev/null 2>&1 || true
}

start_or_restart_service_nb() {
  local svc; svc="$(service_for "$1")"
  systemctl restart --no-block "$svc" >/dev/null 2>&1 || systemctl start --no-block "$svc" >/dev/null 2>&1 || true
}

show_service_debug_if_failed() {
  local svc="$1"
  # Give the unit a brief moment to fail fast (syntax errors, missing helper, etc.)
  sleep 1
  if systemctl is-failed --quiet "$svc" 2>/dev/null; then
    err "Service failed: $svc"
    systemctl --no-pager --full status "$svc" || true
    if have_cmd journalctl; then
      echo
      echo -e "${WHT}Recent logs:${NC}"
      journalctl -u "$svc" -n 80 --no-pager || true
    fi
  fi
}

stop_disable_service() {
  local svc
  svc="$(service_for "$1")"

  systemctl stop "$svc" >/dev/null 2>&1 || true
  systemctl disable "$svc" >/dev/null 2>&1 || true
  systemctl reset-failed "$svc" >/dev/null 2>&1 || true
}

ipsec_reload_all() {
  ipsec rereadsecrets >/dev/null 2>&1 || true
  ipsec reload >/dev/null 2>&1 || true
}

# -----------------------
# Prompts (Create/Edit) - always loops on invalid input
# -----------------------
prompt_role_create() {
  echo "Select server role:"
  echo "  1) Source (Iran)"
  echo "  2) Destination (Kharej)"
  local c
  while true; do
    read -r -p "Enter choice [1-2]: " c || true
    case "${c:-}" in
      1) ROLE="source"; break ;;
      2) ROLE="destination"; break ;;
      *) err "Invalid choice." ;;
    esac
  done
}

prompt_role_edit_keep() {
  echo "Current role: ${ROLE}"
  echo "  1) Source"
  echo "  2) Destination"
  local c
  while true; do
    read -r -p "Change role? (1/2, Enter=keep): " c || true
    [[ -n "${c:-}" ]] || return 0
    case "$c" in
      1) ROLE="source"; return 0 ;;
      2) ROLE="destination"; return 0 ;;
      *) err "Invalid choice." ;;
    esac
  done
}

prompt_tun_name_new() {
  local inp chosen
  while true; do
    read -r -p "VTI interface name [${TUN_NAME_DEFAULT}]: " inp || true
    inp="${inp:-$TUN_NAME_DEFAULT}"
    is_ifname "$inp" || { err "Invalid interface name."; continue; }

    if ! name_taken_anywhere "$inp"; then
      TUN_NAME="$inp"; return 0
    fi

    if [[ "$inp" == "vti" || "$inp" =~ ^vti[0-9]+$ ]]; then
      chosen="$(find_first_free_vti_name vti)" || { err "No free vtiN available."; continue; }
      warn "Name taken. Auto-selected: $chosen"
      TUN_NAME="$chosen"; return 0
    fi

    err "Name '$inp' is already taken."
  done
}

prompt_tun_name_edit_keep_or_rename() {
  local inp
  while true; do
    read -r -p "VTI interface name [${TUN_NAME}] (Enter=keep): " inp || true
    inp="${inp:-$TUN_NAME}"
    is_ifname "$inp" || { err "Invalid interface name."; continue; }

    if [[ "$inp" != "$TUN_NAME" ]] && name_taken_anywhere "$inp"; then
      err "Name '$inp' is already taken."
      continue
    fi
    TUN_NAME="$inp"
    return 0
  done
}

prompt_local_wan_ip() {
  local inp def_if def_ip
  def_if="$(default_iface || true)"
  def_ip=""
  [[ -n "${def_if:-}" ]] && def_ip="$(get_iface_ip "$def_if" || true)"

  while true; do
    if [[ -n "${LOCAL_WAN_IP:-}" ]]; then
      read -r -p "Local public IPv4 [${LOCAL_WAN_IP}]: " inp || true
      inp="${inp:-$LOCAL_WAN_IP}"
    elif [[ -n "${def_ip:-}" ]]; then
      read -r -p "Local public IPv4 (detected: ${def_ip}) [${def_ip}]: " inp || true
      inp="${inp:-$def_ip}"
    else
      read -r -p "Local public IPv4: " inp || true
    fi

    is_ipv4 "${inp:-}" || { err "Invalid IPv4."; continue; }
    LOCAL_WAN_IP="$inp"
    return 0
  done
}

prompt_remote_wan_ip() {
  local inp
  while true; do
    read -r -p "Remote public IPv4 [${REMOTE_WAN_IP:-}]: " inp || true
    inp="${inp:-${REMOTE_WAN_IP:-}}"
    is_ipv4 "${inp:-}" || { err "Invalid IPv4."; continue; }
    REMOTE_WAN_IP="$inp"
    return 0
  done
}

prompt_pair_code_create() {
  echo "PAIR CODE format: 10.X.Y"
  local inp
  while true; do
    read -r -p "PAIR CODE [auto]: " inp || true
    if [[ -z "${inp:-}" ]]; then
      PAIR_CODE="$(generate_pair_code)"
      ok "Generated PAIR CODE: $PAIR_CODE"
      return 0
    fi
    parse_pair_code "$inp" >/dev/null || { err "Invalid PAIR CODE."; continue; }
    PAIR_CODE="$inp"
    return 0
  done
}

prompt_pair_code_edit_keep() {
  echo "PAIR CODE format: 10.X.Y"
  local inp
  while true; do
    read -r -p "PAIR CODE [${PAIR_CODE}] (Enter=keep): " inp || true
    inp="${inp:-$PAIR_CODE}"
    parse_pair_code "$inp" >/dev/null || { err "Invalid PAIR CODE."; continue; }
    PAIR_CODE="$inp"
    return 0
  done
}

prompt_mark_keep() {
  local inp dec
  [[ -n "${MARK:-}" ]] || MARK=$(( (RANDOM % (MARK_MAX - MARK_MIN + 1)) + MARK_MIN ))
  while true; do
    read -r -p "MARK (decimal or 0xHEX) [${MARK}] (Enter=keep): " inp || true
    inp="${inp:-$MARK}"
    is_mark "$inp" || { err "Invalid MARK (use number or 0x... )."; continue; }
    dec="$(mark_to_dec "$inp")"
    [[ "$dec" =~ ^[0-9]+$ ]] && (( dec>=1 && dec<=2147483647 )) || { err "MARK out of range."; continue; }
    MARK="$inp"
    return 0
  done
}

prompt_table_keep() {
  local inp
  [[ -n "${TABLE:-}" ]] || TABLE="$TABLE_DEFAULT"
  while true; do
    read -r -p "Routing TABLE id [${TABLE}] (Enter=keep): " inp || true
    inp="${inp:-$TABLE}"
    [[ "$inp" =~ ^[0-9]+$ ]] && (( inp>=1 && inp<=252 )) || { err "Invalid TABLE (1..252 recommended)."; continue; }
    TABLE="$inp"
    return 0
  done
}

prompt_mtu_keep() {
  local inp
  [[ -n "${MTU:-}" ]] || MTU="$MTU_DEFAULT"
  while true; do
    read -r -p "MTU [${MTU}] (Enter=keep): " inp || true
    inp="${inp:-$MTU}"
    [[ "$inp" =~ ^[0-9]+$ ]] && (( inp>=1200 && inp<=9000 )) || { err "Invalid MTU."; continue; }
    MTU="$inp"
    return 0
  done
}

prompt_tuning_keep() {
  local inp
  [[ -n "${ENABLE_FORWARDING:-}" ]] || ENABLE_FORWARDING="$ENABLE_FORWARDING_DEFAULT"
  [[ -n "${DISABLE_RPFILTER:-}" ]] || DISABLE_RPFILTER="$DISABLE_RPFILTER_DEFAULT"
  [[ -n "${ENABLE_SRC_VALID_MARK:-}" ]] || ENABLE_SRC_VALID_MARK="$ENABLE_SRC_VALID_MARK_DEFAULT"
  [[ -n "${ENABLE_DISABLE_POLICY:-}" ]] || ENABLE_DISABLE_POLICY="$ENABLE_DISABLE_POLICY_DEFAULT"

  while true; do
    read -r -p "Enable IPv4 forwarding? [${ENABLE_FORWARDING}] (yes/no, Enter=keep): " inp || true
    inp="${inp:-$ENABLE_FORWARDING}"
    [[ "$inp" == "yes" || "$inp" == "no" ]] || { err "Invalid value."; continue; }
    ENABLE_FORWARDING="$inp"
    break
  done

  while true; do
    read -r -p "Disable rp_filter? [${DISABLE_RPFILTER}] (yes/no, Enter=keep): " inp || true
    inp="${inp:-$DISABLE_RPFILTER}"
    [[ "$inp" == "yes" || "$inp" == "no" ]] || { err "Invalid value."; continue; }
    DISABLE_RPFILTER="$inp"
    break
  done

  while true; do
    read -r -p "Enable src_valid_mark=1? [${ENABLE_SRC_VALID_MARK}] (yes/no, Enter=keep): " inp || true
    inp="${inp:-$ENABLE_SRC_VALID_MARK}"
    [[ "$inp" == "yes" || "$inp" == "no" ]] || { err "Invalid value."; continue; }
    ENABLE_SRC_VALID_MARK="$inp"
    break
  done

  while true; do
    read -r -p "Enable disable_policy=1 (per VTI iface only)? [${ENABLE_DISABLE_POLICY}] (yes/no, Enter=keep): " inp || true
    inp="${inp:-$ENABLE_DISABLE_POLICY}"
    [[ "$inp" == "yes" || "$inp" == "no" ]] || { err "Invalid value."; continue; }
    ENABLE_DISABLE_POLICY="$inp"
    return 0
  done
}

prompt_psk_keep_or_set() {
  local inp
  while true; do
    if [[ -z "${PSK:-}" ]]; then
      read -r -p "PSK (shared secret) [auto-generate]: " inp || true
      if [[ -z "${inp:-}" ]]; then
        PSK="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32 || true)"
        ok "Generated PSK."
      else
        PSK="$inp"
      fi
    else
      read -r -p "PSK [hidden] (Enter=keep, type new to change): " inp || true
      [[ -n "${inp:-}" ]] && PSK="$inp"
    fi

    ((${#PSK} >= 8)) || { err "PSK too short."; continue; }
    return 0
  done
}

# -----------------------
# Core apply/remove operations
# -----------------------
apply_tunnel_files_and_service() {
  local tun="$1"
  local svc; svc="$(service_for "$tun")"

  write_conf "$tun"
  write_ipsec_conn_conf "$tun"
  write_ipsec_secrets_block "$tun"
  write_sysctl_persist

  enable_service "$tun"

  log "Applying IPsec service..."
  start_or_restart_service_nb "$tun"

  local active="no"
  for _ in 1 2 3; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
      active="yes"
      break
    fi
    sleep 1
  done

  if [ "$active" != "yes" ]; then
    if systemctl is-failed --quiet "$svc" 2>/dev/null; then
      warn "Service is FAILED for now (peer probably not ready). The monitor timer will keep retrying automatically."
    else
      warn "Service is not active yet (maybe negotiating). It should become active once the peer is ready."
    fi
  fi

  ipsec_reload_all

  # (Optional) Only show debug if user explicitly asked for verbose/debug
  # if [ "${DEBUG:-0}" = "1" ]; then
  #   show_service_debug_if_failed "$svc"
  # fi
}

iptables_delete_all_marks_for_if() {
  local ifc="$1"
  local line

  while true; do
    line="$(iptables -t mangle -S OUTPUT 2>/dev/null | grep -E -- "-o ${ifc}\b.*-j MARK --set-xmark" | head -n1)"
    [[ -z "$line" ]] && break
    iptables -t mangle ${line/-A /-D } 2>/dev/null || true
  done

  while true; do
    line="$(iptables -t mangle -S PREROUTING 2>/dev/null | grep -E -- "-i ${ifc}\b.*-j MARK --set-xmark" | head -n1)"
    [[ -z "$line" ]] && break
    iptables -t mangle ${line/-A /-D } 2>/dev/null || true
  done
}

delete_ip_rules_for_mark_table() {
  local mark_dec="$1"
  local table="$2"

  # هر rule که fwmark=mark_dec و lookup table دارد حذف می‌کنیم
  ip rule show | awk -v m="$mark_dec" -v t="$table" '
    $0 ~ ("fwmark " m) && $0 ~ (" lookup " t) {print $1}
  ' | sed 's/://' | while read -r pref; do
    ip rule del pref "$pref" 2>/dev/null || true
  done
}

delete_routes_for_if_in_table() {
  local ifc="$1"
  local table="$2"

  # Remove any routes in table that point to this interface (best-effort)
  ip -4 route show table "$table" 2>/dev/null | awk -v dev="$ifc" '
    $0 ~ (" dev " dev) {print}
  ' | while read -r line; do
    # line is a full route entry, delete it
    ip -4 route del table "$table" $line 2>/dev/null || true
  done

  ip route flush cache >/dev/null 2>&1 || true
}

remove_tunnel_everything() {
  local tun="$1"
  read_conf "$tun" || true

  local ifc="${TUN_NAME:-$tun}"
  local mark_dec=""
  local table="${TABLE:-220}"

  if [[ -n "${MARK:-}" ]]; then
    mark_dec="$(mark_to_dec "${MARK}")"
  fi

  stop_disable_service "$tun"

  if [[ -x /usr/local/sbin/simple-ipsec-down ]]; then
    /usr/local/sbin/simple-ipsec-down "$tun" >/dev/null 2>&1 || true
  fi

  iptables_delete_all_marks_for_if "$ifc"

  if [[ -n "${mark_dec:-}" ]]; then
    delete_ip_rules_for_mark_table "$mark_dec" "$table"
  fi
  # also delete any leftover routes in the table pointing to this interface
  delete_routes_for_if_in_table "$ifc" "$table"

  ip link set "$ifc" down >/dev/null 2>&1 || true
  ip link del "$ifc" >/dev/null 2>&1 || true

  rm -f "$(ipsec_conn_conf_for "$tun")" >/dev/null 2>&1 || true
  remove_secrets_block "$tun"
  rm -f "$(conf_path_for "$tun")" >/dev/null 2>&1 || true

  write_sysctl_persist
  ipsec_reload_all
}

# -----------------------
# Actions (menu)
# -----------------------
do_list() {
  echo -e "${MAG}===== Tunnels =====${NC}"
  local found="no" t
  while IFS= read -r t; do
    [[ -n "$t" ]] && { echo " - $t"; found="yes"; }
  done < <(list_tunnels)
  [[ "$found" == "yes" ]] || warn "No tunnels configured."
}

do_info() {
  choose_tunnel || return 0
  local tun="$SELECTED_TUN"
  read_conf "$tun" || { err "Config not found."; return; }

  echo -e "${MAG}===== IPsec(VTI) Info: ${tun} =====${NC}"
  echo "Role:                   $ROLE"
  echo "Pair code:              $PAIR_CODE"
  echo "Tunnel name:            $TUN_NAME"
  echo "Local public IP:        $LOCAL_WAN_IP"
  echo "Remote public IP:       $REMOTE_WAN_IP"
  echo "Local tunnel CIDR:      $TUN_LOCAL_CIDR"
  echo "Remote tunnel IP:       $TUN_REMOTE_IP"
  echo "MARK:                   $MARK"
  echo "Routing TABLE id:       $TABLE"
  echo "Rule pref:              ${RULE_PREF:-}"
  echo "MTU:                    $MTU"
  echo "IPv4 forwarding:        $ENABLE_FORWARDING"
  echo "rp_filter disabled:     $DISABLE_RPFILTER"
  echo "src_valid_mark enabled: $ENABLE_SRC_VALID_MARK"
  echo "disable_policy enabled: $ENABLE_DISABLE_POLICY"
  echo "Config file:            $(conf_path_for "$tun")"
  echo "IPsec conn file:        $(ipsec_conn_conf_for "$tun")"
  echo

  echo -e "${CYA}COPY BLOCK (paste on the other server):${NC}"
  warn "COPY BLOCK includes PSK. Keep it private."
  print_copy_block
}

do_status_one() {
  choose_tunnel || return 0
  local tun="$SELECTED_TUN"
  read_conf "$tun" || { err "Config not found."; return; }

  echo -e "${MAG}===== Status: ${tun} =====${NC}"
  local svc mark_hex MARK_DEC
  svc="$(service_for "$tun")"
  if systemctl is-active --quiet "$svc"; then
    echo -e "Service: ${GRN}active${NC}"
  else
    echo -e "Service: ${RED}inactive${NC}"
  fi
  if ip link show "$tun" >/dev/null 2>&1; then
    echo -e "Interface: ${GRN}present${NC}"
  else
    echo -e "Interface: ${RED}missing${NC}"
  fi

  MARK_DEC="$(mark_to_dec "$MARK")"
  mark_hex=$(printf "0x%08x" "$MARK_DEC")

  if ip xfrm state 2>/dev/null | grep -q "mark ${mark_hex}"; then
    echo -e "XFRM state: ${GRN}present${NC}"
  elif ip xfrm state 2>/dev/null | grep -qE "src ${LOCAL_WAN_IP}[[:space:]]+dst ${REMOTE_WAN_IP}|src ${REMOTE_WAN_IP}[[:space:]]+dst ${LOCAL_WAN_IP}"; then
    echo -e "XFRM state: ${GRN}present${NC}"
  else
    echo -e "XFRM state: ${RED}missing${NC}"
  fi

  if ping -c 1 -W 1 "$TUN_REMOTE_IP" >/dev/null 2>&1; then
    echo -e "Ping: ${GRN}OK${NC} (${TUN_REMOTE_IP})"
  else
    echo -e "Ping: ${RED}FAIL${NC} (${TUN_REMOTE_IP})"
  fi
  echo
  echo -e "${WHT}Service:${NC}"
  systemctl --no-pager --full status "$(service_for "$tun")" || true
  echo

  if have_cmd journalctl; then
    echo -e "${WHT}Recent unit logs:${NC}"
    journalctl -u "$svc" -n 80 --no-pager || true
    echo

    echo -e "${WHT}Recent strongSwan logs:${NC}"
    journalctl -u strongswan-starter.service -n 80 --no-pager \
      || journalctl -u strongswan.service -n 80 --no-pager \
      || true
    echo
  fi

  echo -e "${WHT}Interface:${NC}"
  ip -d link show "$tun" 2>/dev/null || { warn "Interface '$tun' not found (service may be down)."; }
  ip -4 addr show dev "$tun" 2>/dev/null || true
  echo

  echo -e "${WHT}Counters:${NC}"
  ip -s link show "$tun" 2>/dev/null || true
  echo

  echo -e "${WHT}IPsec status (top):${NC}"
  ipsec statusall | sed -n '1,90p' || true
  echo

  echo -e "${WHT}Ping remote tunnel IP:${NC} ${TUN_REMOTE_IP}"
  if ping -c 3 -W 2 "$TUN_REMOTE_IP" >/dev/null 2>&1; then
    ok "Ping OK."
  else
    warn "Ping failed. (If SA is up but bytes=0, XFRM policy auto-fix should solve it; try restart service.)"
  fi
}

do_status_all() {
  echo -e "${MAG}===== Status: ALL Tunnels =====${NC}"
  local t any="no"
  while IFS= read -r t; do
    [[ -n "$t" ]] || continue
    any="yes"
    echo -e "${CYA}--- ${t} ---${NC}"
    if read_conf "$t"; then
      local svc mark_hex MARK_DEC
      svc="$(service_for "$t")"

      # Service status (systemd oneshot may be "active (exited)" after a successful start)
      if systemctl is-active --quiet "$svc"; then
        echo -e "Service: ${GRN}active${NC}"
      else
        echo -e "Service: ${RED}inactive${NC}"
      fi

      if ip link show "$t" >/dev/null 2>&1; then
        echo -e "Interface: ${GRN}present${NC}"
      else
        echo -e "Interface: ${RED}missing${NC}"
      fi

      # XFRM state for this tunnel mark
      MARK_DEC="$(mark_to_dec "$MARK")"
      mark_hex=$(printf "0x%08x" "$MARK_DEC")
      if ip xfrm state 2>/dev/null | grep -q "mark ${mark_hex}"; then
        echo -e "XFRM state: ${GRN}present${NC}"
      elif ip xfrm state 2>/dev/null | grep -qE "src ${LOCAL_WAN_IP}[[:space:]]+dst ${REMOTE_WAN_IP}|src ${REMOTE_WAN_IP}[[:space:]]+dst ${LOCAL_WAN_IP}"; then
        echo -e "XFRM state: ${GRN}present${NC}"
      else
        echo -e "XFRM state: ${RED}missing${NC}"
      fi

      # Tunnel health
      if ping -c 1 -W 1 "$TUN_REMOTE_IP" >/dev/null 2>&1; then
        echo -e "Tunnel: ${GRN}active${NC} (ping OK)"
      else
        echo -e "Tunnel: ${RED}inactive${NC} (ping failed)"
      fi

      echo "Tunnel IP: ${TUN_LOCAL_CIDR} -> ${TUN_REMOTE_IP}"
      echo "MARK/TABLE: ${MARK} / ${TABLE} (pref=${RULE_PREF:-})"
    else
      echo "Config: missing"
    fi
    echo
  done < <(list_tunnels)
  [[ "$any" == "yes" ]] || warn "No tunnels configured."
}

do_create() {
  log "Create NEW IPsec(VTI) tunnel"
  echo

  ROLE=""; TUN_NAME=""; LOCAL_WAN_IP=""; REMOTE_WAN_IP=""
  PAIR_CODE=""; MARK=""; TABLE="$TABLE_DEFAULT"; MTU="$MTU_DEFAULT"
  ENABLE_FORWARDING="$ENABLE_FORWARDING_DEFAULT"
  DISABLE_RPFILTER="$DISABLE_RPFILTER_DEFAULT"
  ENABLE_SRC_VALID_MARK="$ENABLE_SRC_VALID_MARK_DEFAULT"
  ENABLE_DISABLE_POLICY="$ENABLE_DISABLE_POLICY_DEFAULT"
  PSK=""
  PASTE_SOURCE_PUBLIC_IP=""; PASTE_DEST_PUBLIC_IP=""

  prompt_role_create
  echo

  prompt_paste_copy_block || { err "COPY BLOCK parse failed."; return; }
  echo

  prompt_tun_name_new
  echo

  if [[ -n "${PASTE_SOURCE_PUBLIC_IP:-}" && -n "${PASTE_DEST_PUBLIC_IP:-}" ]]; then
    if [[ "$ROLE" == "source" ]]; then
      LOCAL_WAN_IP="$PASTE_SOURCE_PUBLIC_IP"
      REMOTE_WAN_IP="$PASTE_DEST_PUBLIC_IP"
    else
      LOCAL_WAN_IP="$PASTE_DEST_PUBLIC_IP"
      REMOTE_WAN_IP="$PASTE_SOURCE_PUBLIC_IP"
    fi
    ok "Public IPs imported from COPY BLOCK."
  fi

  prompt_local_wan_ip
  prompt_remote_wan_ip

  if [[ -z "${PAIR_CODE:-}" ]]; then
    prompt_pair_code_create
  else
    parse_pair_code "$PAIR_CODE" >/dev/null || { err "Invalid PAIR_CODE from COPY BLOCK."; return; }
  fi
  recompute_tunnel_ips_from_pair || return

  prompt_mark_keep
  prompt_table_keep
  prompt_mtu_keep
  prompt_tuning_keep
  prompt_psk_keep_or_set

  ensure_strongswan_includes
  ensure_systemd_template
  with_lock apply_tunnel_files_and_service "$TUN_NAME"

  ok "Tunnel '${TUN_NAME}' created & applied."
  echo
  echo -e "${GRN}Tunnel addressing:${NC}"
  echo "  PAIR_CODE:         ${PAIR_CODE}"
  echo "  Local CIDR:        ${TUN_LOCAL_CIDR}"
  echo "  Remote tunnel IP:  ${TUN_REMOTE_IP}"
  echo
  echo -e "${CYA}COPY BLOCK (paste on the other server):${NC}"
  warn "COPY BLOCK includes PSK. Keep it private."
  print_copy_block
}

do_edit() {
  choose_tunnel || return 0
  local old_tun="$SELECTED_TUN"
  read_conf "$old_tun" || { err "Config not found for: $old_tun"; return; }

  log "Edit tunnel: $old_tun"
  warn "Press Enter to keep existing values."
  echo

  local old_role="$ROLE"
  local old_pair="$PAIR_CODE"
  local old_mark="$MARK"
  local old_table="$TABLE"
  local old_mtu="$MTU"
  local old_fwd="$ENABLE_FORWARDING"
  local old_rpf="$DISABLE_RPFILTER"
  local old_svm="$ENABLE_SRC_VALID_MARK"
  local old_dp="$ENABLE_DISABLE_POLICY"
  local old_psk="$PSK"
  local old_name="$TUN_NAME"

  prompt_role_edit_keep
  prompt_pair_code_edit_keep
  recompute_tunnel_ips_from_pair || { ROLE="$old_role"; PAIR_CODE="$old_pair"; return; }

  prompt_tun_name_edit_keep_or_rename
  prompt_local_wan_ip
  prompt_remote_wan_ip

  prompt_mark_keep
  prompt_table_keep
  prompt_mtu_keep
  prompt_tuning_keep
  prompt_psk_keep_or_set

  ensure_strongswan_includes
  ensure_systemd_template

  if [[ "$TUN_NAME" != "$old_tun" ]]; then
    warn "Renaming tunnel: ${old_tun} -> ${TUN_NAME}"
    with_lock remove_tunnel_everything "$old_tun"
  else
    with_lock stop_disable_service "$old_tun" >/dev/null 2>&1 || true
  fi

  with_lock apply_tunnel_files_and_service "$TUN_NAME"

  ok "Tunnel updated & applied: ${TUN_NAME}"
  echo
  echo -e "${CYA}COPY BLOCK (paste on the other server):${NC}"
  warn "COPY BLOCK includes PSK. Keep it private."
  print_copy_block
}

do_force_fix_one() {
  choose_tunnel || return 0
  local tun="$SELECTED_TUN"
  read_conf "$tun" || { err "Config not found."; return; }

  log "Force repair XFRM policies for: $tun"
  if [[ -x /usr/local/sbin/simple-ipsec-fix ]]; then
    /usr/local/sbin/simple-ipsec-fix "$tun" || true
  else
    warn "Fix helper not found; restarting service as fallback."
    timeout "${SYSTEMCTL_RESTART_TIMEOUT}" systemctl restart "$(service_for "$tun")" >/dev/null 2>&1 || true
  fi
}

do_force_fix_all() {
  log "Force repair XFRM policies for ALL tunnels"
  local t any="no"
  while IFS= read -r t; do
    [[ -n "$t" ]] || continue
    any="yes"
    if [[ -x /usr/local/sbin/simple-ipsec-fix ]]; then
      echo -e "${CYA}--- ${t} ---${NC}"
      /usr/local/sbin/simple-ipsec-fix "$t" || true
      echo
    else
      timeout "${SYSTEMCTL_RESTART_TIMEOUT}" systemctl restart "$(service_for "$t")" >/dev/null 2>&1 || true
    fi
  done < <(list_tunnels)
  [[ "$any" == "yes" ]] || warn "No tunnels configured."
}

do_delete() {
  choose_tunnel || return 0
  local tun="$SELECTED_TUN"

  warn "Delete tunnel '$tun' (service + interface + ipsec conn + secrets block + config + rules)."
  local yn
  while true; do
    read -r -p "Are you sure? [y/N]: " yn || true
    yn="${yn:-N}"
    case "$yn" in
      y|Y) break ;;
      n|N) log "Canceled."; return ;;
      *) err "Invalid answer. Type y or n." ;;
    esac
  done

  with_lock remove_tunnel_everything "$tun"
  ok "Deleted tunnel: $tun"
}

banner() {
  echo -e "${MAG}========================================${NC}"
  echo -e "${WHT}  ${APP_NAME}${NC}  ${CYA}(IKEv2 + VTI | Multi Tunnel)${NC}"
  echo -e "${YEL}  Repo:${NC} ${BLU}${REPO_URL}${NC}"
  echo -e "${MAG}========================================${NC}"
}

menu() {
  while true; do
    clear || true
    banner
    echo -e "${CYA}1)${NC} Create tunnel (new)"
    echo -e "${CYA}2)${NC} Edit tunnel"
    echo -e "${CYA}3)${NC} Status (one tunnel)"
    echo -e "${CYA}4)${NC} Status (ALL tunnels)"
    echo -e "${CYA}5)${NC} Info / COPY BLOCK (one tunnel)"
    echo -e "${CYA}6)${NC} Force fix policies (one tunnel)"
    echo -e "${CYA}7)${NC} Force fix policies (ALL tunnels)"
    echo -e "${CYA}8)${NC} List tunnels"
    echo -e "${CYA}9)${NC} Delete tunnel"
    echo -e "${CYA}0)${NC} Exit"
    echo -e "${MAG}----------------------------------------${NC}"
    local choice
    read -r -p "Select an option [0-9]: " choice || true
    case "${choice:-}" in
      1) do_create || true; pause ;;
      2) do_edit || true; pause ;;
      3) do_status_one || true; pause ;;
      4) do_status_all || true; pause ;;
      5) do_info || true; pause ;;
      6) do_force_fix_one || true; pause ;;
      7) do_force_fix_all || true; pause ;;
      8) do_list || true; pause ;;
      9) do_delete || true; pause ;;
      0) exit 0 ;;
      *) err "Invalid selection."; pause ;;
    esac
  done
}

main() {
  require_root
  require_cmds
  ensure_dirs
  ensure_strongswan_service_running
  ensure_strongswan_includes
  ensure_systemd_template
  ensure_monitor_units
  write_sysctl_persist
  menu
}

main "$@"
