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

# New: activation + healthcheck units/helpers
ACTIVATE_SERVICE_TEMPLATE="/etc/systemd/system/simple-ipsec-activate@.service"
ACTIVATE_TIMER_TEMPLATE="/etc/systemd/system/simple-ipsec-activate@.timer"
HEALTH_SERVICE_TEMPLATE="/etc/systemd/system/simple-ipsec-health@.service"
HEALTH_TIMER_TEMPLATE="/etc/systemd/system/simple-ipsec-health@.timer"
ACTIVATE_HELPER="/usr/local/sbin/simple-ipsec-activate"
HEALTH_HELPER="/usr/local/sbin/simple-ipsec-health"

# Defaults
TUN_NAME_DEFAULT="vti0"
MTU_DEFAULT="1380"
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

# Activation/Health defaults (can override via env)
ACTIVATE_RETRY_SEC="${ACTIVATE_RETRY_SEC:-20}"                 # activation timer interval
ACTIVATE_INITIAL_DELAY_SEC="${ACTIVATE_INITIAL_DELAY_SEC:-10}" # first activation after create/edit
HEALTH_INTERVAL_SEC="${HEALTH_INTERVAL_SEC:-30}"               # health timer interval

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
  local mark_dec table
  mark_dec="$(mark_to_dec "$1")"
  table="$2"
  echo $((10000 + (table % 50)*1000 + (mark_dec % 1000)))
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
activate_timer_for() { echo "simple-ipsec-activate@${1}.timer"; }
health_timer_for() { echo "simple-ipsec-health@${1}.timer"; }

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
LOCAL_ID="${LOCAL_ID}"
REMOTE_ID="${REMOTE_ID}"
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

# IDs must be consistent on both sides:
# source side expects remote "destination", destination side expects remote "source"
compute_ids_from_pair() {
  # produce LOCAL_ID + REMOTE_ID
  # use PAIR_CODE but make it filename/ID safe: 10.X.Y -> 10-X-Y
  local pc_safe
  pc_safe="${PAIR_CODE//./-}"
  if [[ "$ROLE" == "source" ]]; then
    LOCAL_ID="@simple-ipsec-${pc_safe}-source"
    REMOTE_ID="@simple-ipsec-${pc_safe}-destination"
  else
    LOCAL_ID="@simple-ipsec-${pc_safe}-destination"
    REMOTE_ID="@simple-ipsec-${pc_safe}-source"
  fi
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

  compute_ids_from_pair
}

local_tun_ip_from_cidr() { echo "${TUN_LOCAL_CIDR%%/*}"; }

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
        echo -e "${MAG}Please press Enter one more time to finish.${NC}"
        continue
      fi
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

  {
    echo "$begin"
    echo "# Peer pair: ${LOCAL_WAN_IP} <-> ${REMOTE_WAN_IP}"
    echo "# IDs: ${LOCAL_ID} <-> ${REMOTE_ID}"
    # IMPORTANT: Use IDs (not IP pair) to avoid ambiguous matches when multiple conns share same public IPs.
    echo "${LOCAL_ID} ${REMOTE_ID} : PSK \"${PSK}\""
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
  local lip; lip="$(local_tun_ip_from_cidr)"

  cat >"$(ipsec_conn_conf_for "$tun")" <<EOF
# generated by simple-ipsec
conn ${conn_name}
  keyexchange=ikev2
  type=tunnel
  auto=start
  authby=psk

  left=${LOCAL_WAN_IP}
  right=${REMOTE_WAN_IP}

  # Unique IDs per tunnel (prevents PSK ambiguity when multiple conns share same public IPs)
  leftid=${LOCAL_ID}
  rightid=${REMOTE_ID}

  # Route-based (policy routing via mark)
  mark=${MARK}
  installpolicy=no

  # Unique TS per tunnel (prevents duplicate CHILD_SA with same selectors)
  leftsubnet=${lip}/32
  rightsubnet=${TUN_REMOTE_IP}/32

  ## FIX P1: Make crypto proposals more flexible and modern.
  ## Removed '!' and added modern GCM ciphers first.
  ike=aes256gcm16-sha256-modp2048,aes256-sha256-modp2048
  esp=aes256gcm16-sha256,aes256-sha256

  dpdaction=restart
  dpddelay=30s
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

  local sysctl_d="/etc/sysctl.d/99-simple-ipsec.conf"
  ln -sf "$SYSCTL_FILE" "$sysctl_d" >/dev/null 2>&1 || true

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

TimeoutStartSec=45
TimeoutStopSec=30

ExecStart=/usr/local/sbin/simple-ipsec-up %i
ExecStop=/usr/local/sbin/simple-ipsec-down %i

[Install]
WantedBy=multi-user.target
EOF

  # -----------------------
  # ACTIVATE: tries to start tunnel after create/edit, without making the manager do it inline
  # -----------------------
  cat >"$ACTIVATE_SERVICE_TEMPLATE" <<'EOF'
[Unit]
Description=Simple IPsec Tunnel - Activation helper (%i)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/simple-ipsec-activate %i
EOF

  cat >"$ACTIVATE_TIMER_TEMPLATE" <<EOF
[Unit]
Description=Simple IPsec Tunnel - Activation timer (%i)

[Timer]
OnBootSec=${ACTIVATE_INITIAL_DELAY_SEC}
OnUnitActiveSec=${ACTIVATE_RETRY_SEC}
AccuracySec=1s
RandomizedDelaySec=2s
Unit=simple-ipsec-activate@%i.service

[Install]
WantedBy=timers.target
EOF

  # -----------------------
  # HEALTH: periodic check to keep service active and ping OK; auto fix policies when ping fails
  # -----------------------
  cat >"$HEALTH_SERVICE_TEMPLATE" <<'EOF'
[Unit]
Description=Simple IPsec Tunnel - Health check (%i)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/simple-ipsec-health %i
EOF

  cat >"$HEALTH_TIMER_TEMPLATE" <<EOF
[Unit]
Description=Simple IPsec Tunnel - Health timer (%i)

[Timer]
OnBootSec=15
OnUnitActiveSec=${HEALTH_INTERVAL_SEC}
AccuracySec=1s
RandomizedDelaySec=3s
Unit=simple-ipsec-health@%i.service

[Install]
WantedBy=timers.target
EOF

  # -----------------------
  # UP helper
  # -----------------------
  cat >"$UP_HELPER" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

IPSEC_UP_TIMEOUT="${IPSEC_UP_TIMEOUT:-12}"          # seconds per try
IPSEC_UP_TRIES="${IPSEC_UP_TRIES:-2}"              # retries
WAIT_LOCAL_IP_MAX="${WAIT_LOCAL_IP_MAX:-15}"        # seconds
XFRM_STATE_WAIT="${XFRM_STATE_WAIT:-6}"             # seconds

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
  key_dec="$(mark_to_dec "${MARK}")"

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

# ensure_tunnel_routes() { true; }
# ensure_mangle_mark_rules() { true; }

ensure_tunnel_routes() {
  # Only make the tunnel endpoint reachable via the VTI itself.
  # This is the safest mode for "just tunnel IP <-> tunnel IP" and works for multi tunnels too.
  local lip rip
  lip="$(local_tun_ip)"
  rip="${TUN_REMOTE_IP}"

  # Route remote tunnel IP via VTI; force source to local tunnel IP
  ip -4 route replace "${rip}/32" dev "${TUN_NAME}" src "${lip}" 2>/dev/null || true

  # Some kernels need an explicit scope link for point-to-point behavior
  # (harmless if not needed)
  ip -4 route replace "${rip}/32" dev "${TUN_NAME}" scope link src "${lip}" 2>/dev/null || true
}

ensure_mangle_mark_rules() {
  # Not needed for "only tunnel IP" mode.
  true
}

mark_hex_from_conf() {
  local md
  md="$(mark_to_dec "${MARK}")"
  printf "0x%x" "$md"
}

xfrm_state_present() {
  local mh hx
  mh="$(mark_hex_from_conf)"
  hx="${mh#0x}"
  ip xfrm state 2>/dev/null | grep -Eqi "mark 0x0*${hx}/0xffffffff"
}

wait_for_xfrm_state() {
  local i
  for i in $(seq 1 "${XFRM_STATE_WAIT}"); do
    xfrm_state_present && return 0
    sleep 1
  done
  return 1
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
    warn "ipsec up failed (try ${i})."
    sleep 1
  done

  err "IPsec did not come up."
  echo
  warn "ipsec statusall (top):"
  timeout 8 ipsec statusall | sed -n '1,140p' || true
  exit 1
}

xfrm_state_mark_dec() {
  local mh m
  mh="$(mark_hex_from_conf)"
  m="$(ip xfrm state 2>/dev/null | awk -v mh="${mh}" '
    $1=="src" {inblk=1}
    inblk && $1=="mark" && $2 ~ mh {print $2; exit}
    inblk && /^$/ {inblk=0}
  ' | head -n1)"
  [[ -n "${m:-}" ]] || return 0
  m="${m%%/*}"
  if [[ "$m" =~ ^0x ]]; then echo $((16#${m#0x})); else echo "$m"; fi
}

xfrm_reqid_from_state() {
  local mh reqid
  mh="$(mark_hex_from_conf)"
  reqid="$(ip xfrm state 2>/dev/null | awk -v mh="${mh}" '
    $1=="src" {inblk=1}
    inblk && $1=="mark" && $2 ~ mh {markok=1}
    inblk && markok && $1=="proto" && $2=="esp" {
      for(i=1;i<=NF;i++) if($i=="reqid") {print $(i+1); exit}
    }
    inblk && /^$/ {inblk=0; markok=0}
  ' | head -n1)"
  reqid="${reqid%%(*}"
  reqid="${reqid//[^0-9]/}"
  [[ -n "${reqid:-}" ]] || return 0
  echo "$reqid"
}

xfrm_policy_install_tunnel_ips() {
  local lip rip reqid mark_dec_effective
  lip="$(local_tun_ip)"
  rip="${TUN_REMOTE_IP}"

  mark_dec_effective="$(xfrm_state_mark_dec || true)"
  [[ -n "${mark_dec_effective:-}" ]] || mark_dec_effective="$(mark_to_dec "${MARK}")"

  reqid="$(xfrm_reqid_from_state || true)"
  [[ -n "${reqid:-}" ]] || reqid="1"

  ip xfrm policy delete src "${lip}/32" dst "${rip}/32" dir out mark "${mark_dec_effective}" mask 0xffffffff 2>/dev/null || true
  ip xfrm policy delete src "${rip}/32" dst "${lip}/32" dir in  mark "${mark_dec_effective}" mask 0xffffffff 2>/dev/null || true
  ip xfrm policy delete src "${lip}/32" dst "${rip}/32" dir fwd mark "${mark_dec_effective}" mask 0xffffffff 2>/dev/null || true
  ip xfrm policy delete src "${lip}/32" dst "${rip}/32" dir out 2>/dev/null || true
  ip xfrm policy delete src "${rip}/32" dst "${lip}/32" dir in  2>/dev/null || true
  ip xfrm policy delete src "${lip}/32" dst "${rip}/32" dir fwd 2>/dev/null || true

  ip xfrm policy add src "${lip}/32" dst "${rip}/32" dir out \
    mark "${mark_dec_effective}" mask 0xffffffff \
    tmpl src "${LOCAL_WAN_IP}"  dst "${REMOTE_WAN_IP}" proto esp reqid "${reqid}" mode tunnel 2>/dev/null || true

  ip xfrm policy add src "${rip}/32" dst "${lip}/32" dir in \
    mark "${mark_dec_effective}" mask 0xffffffff \
    tmpl src "${REMOTE_WAN_IP}" dst "${LOCAL_WAN_IP}" proto esp reqid "${reqid}" mode tunnel 2>/dev/null || true

  ip xfrm policy add src "${lip}/32" dst "${rip}/32" dir fwd \
    mark "${mark_dec_effective}" mask 0xffffffff \
    tmpl src "${LOCAL_WAN_IP}"  dst "${REMOTE_WAN_IP}" proto esp reqid "${reqid}" mode tunnel 2>/dev/null || true
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
  err "No XFRM state found for this tunnel MARK after IPsec up. Tunnel is not established."
  echo
  warn "ip xfrm state:"
  ip xfrm state 2>/dev/null || true
  echo
  warn "ipsec statusall (top):"
  timeout 8 ipsec statusall | sed -n '1,140p' || true
  exit 1
fi

# Try ping first; if it fails, reinstall policies once.
if ! ping -c 1 -W 1 "${TUN_REMOTE_IP}" >/dev/null 2>&1; then
  warn "Ping failed right after SA up; reinstalling XFRM endpoint policies..."
  xfrm_policy_install_tunnel_ips
fi

log "Tunnel is up (XFRM state present for MARK)."
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
local_tun_ip() { echo "${TUN_LOCAL_CIDR%%/*}"; }

mark_hex_from_conf() {
  local md
  md="$(mark_to_dec "${MARK}")"
  printf "0x%x" "$md"
}

xfrm_state_mark_dec() {
  local mh hx re m
  mh="$(mark_hex_from_conf)"
  hx="${mh#0x}"
  re="^0x0*${hx}/0xffffffff$"

  m="$(ip xfrm state 2>/dev/null | awk -v re="${re}" '
    $1=="src" {inblk=1}
    inblk && $1=="mark" && $2 ~ re {print $2; exit}
    inblk && /^$/ {inblk=0}
  ' | head -n1)"

  [[ -n "${m:-}" ]] || return 0
  m="${m%%/*}"
  if [[ "$m" =~ ^0x ]]; then echo $((16#${m#0x})); else echo "$m"; fi
}

cleanup_firewall_rules() {
    local other_tunnel_count
    other_tunnel_count=$(find "$TUNNELS_DIR" -maxdepth 1 -name "*.conf" -not -name "${tun}.conf" | wc -l)

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
  local line
  while true; do
    line="$(
      iptables -t mangle -S OUTPUT 2>/dev/null |
        grep -E -- "^-A OUTPUT\b.*\b-d ${TUN_REMOTE_IP}(/32)?\b.*\b-j (MARK|CONNMARK)\b" |
        head -n1
    )"
    [[ -z "${line:-}" ]] && break
    iptables -t mangle ${line/-A /-D } 2>/dev/null || true
  done

  while true; do
    line="$(
      iptables -t mangle -S OUTPUT 2>/dev/null |
        grep -E -- "^-A OUTPUT\b.*\b-o ${TUN_NAME}\b.*\b-j (MARK|CONNMARK)\b" |
        head -n1
    )"
    [[ -z "${line:-}" ]] && break
    iptables -t mangle ${line/-A /-D } 2>/dev/null || true
  done

  while true; do
    line="$(
      iptables -t mangle -S PREROUTING 2>/dev/null |
        grep -E -- "^-A PREROUTING\b.*\b-i ${TUN_NAME}\b.*\b-j (MARK|CONNMARK)\b" |
        head -n1
    )"
    [[ -z "${line:-}" ]] && break
    iptables -t mangle ${line/-A /-D } 2>/dev/null || true
  done

  while true; do
    line="$(
      iptables -t mangle -S POSTROUTING 2>/dev/null |
        grep -E -- "^-A POSTROUTING\b.*\b-o ${TUN_NAME}\b.*\b-j (MARK|CONNMARK)\b" |
        head -n1
    )"
    [[ -z "${line:-}" ]] && break
    iptables -t mangle ${line/-A /-D } 2>/dev/null || true
  done
}

cleanup_xfrm_policies() {
  local lip rip mark_dec_effective
  lip="$(local_tun_ip)"
  rip="${TUN_REMOTE_IP}"

  mark_dec_effective="$(xfrm_state_mark_dec || true)"
  [[ -n "${mark_dec_effective:-}" ]] || mark_dec_effective="$(mark_to_dec "${MARK}")"

  ip xfrm policy delete src "${lip}/32" dst "${rip}/32" dir out mark "${mark_dec_effective}" mask 0xffffffff 2>/dev/null || true
  ip xfrm policy delete src "${rip}/32" dst "${lip}/32" dir in  mark "${mark_dec_effective}" mask 0xffffffff 2>/dev/null || true
  ip xfrm policy delete src "${lip}/32" dst "${rip}/32" dir fwd mark "${mark_dec_effective}" mask 0xffffffff 2>/dev/null || true
  ip xfrm policy delete src "${lip}/32" dst "${rip}/32" dir out 2>/dev/null || true
  ip xfrm policy delete src "${rip}/32" dst "${lip}/32" dir in  2>/dev/null || true
  ip xfrm policy delete src "${lip}/32" dst "${rip}/32" dir fwd 2>/dev/null || true
}

cleanup_policy_routing() {
  local subnet
  subnet="$(echo "${TUN_LOCAL_CIDR%/*}" | awk -F. '{print $1"."$2"."$3".0/30"}')"
  ip -4 route del "${subnet}" dev "${TUN_NAME}" 2>/dev/null || true
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
  local FIX_HELPER="/usr/local/sbin/simple-ipsec-fix"
  cat >"$FIX_HELPER" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

IPSEC_UP_TIMEOUT="${IPSEC_UP_TIMEOUT:-12}"
IPSEC_UP_TRIES="${IPSEC_UP_TRIES:-2}"
XFRM_STATE_WAIT="${XFRM_STATE_WAIT:-6}"

APP_DIR="/etc/simple-ipsec"
TUNNELS_DIR="$APP_DIR/tunnels.d"

tun="${1:-}"
[[ -n "${tun}" ]] || { echo "Usage: simple-ipsec-fix <tunnel_name>" >&2; exit 2; }

CONF_FILE="$TUNNELS_DIR/${tun}.conf"
[[ -f "$CONF_FILE" ]] || { echo "Config not found: $CONF_FILE" >&2; exit 1; }
# shellcheck disable=SC1090
source "$CONF_FILE"

conn_name="simple-ipsec-${tun}"

log()  { echo "[simple-ipsec-fix:${tun}] $*"; }
warn() { echo "[simple-ipsec-fix:${tun}][WARN] $*" >&2; }
err()  { echo "[simple-ipsec-fix:${tun}][ERROR] $*" >&2; }

mark_to_dec() {
  local m="$1"
  if [[ "$m" =~ ^0x ]]; then echo $((16#${m#0x})); else echo "$m"; fi
}
local_tun_ip() { echo "${TUN_LOCAL_CIDR%%/*}"; }

mark_hex_from_conf() {
  local md
  md="$(mark_to_dec "${MARK}")"
  printf "0x%x" "$md"
}

xfrm_state_present() {
  local mh hx re
  mh="$(mark_hex_from_conf)"
  hx="${mh#0x}"
  re="mark 0x0*${hx}/0xffffffff"
  ip xfrm state 2>/dev/null | grep -Eqi "$re"
}

wait_for_xfrm_state() {
  local i
  for i in $(seq 1 "${XFRM_STATE_WAIT}"); do
    xfrm_state_present && return 0
    sleep 1
  done
  return 1
}

xfrm_state_mark_dec() {
  local mh hx re m
  mh="$(mark_hex_from_conf)"
  hx="${mh#0x}"
  re="^0x0*${hx}/0xffffffff$"

  m="$(ip xfrm state 2>/dev/null | awk -v re="${re}" '
    $1=="src" {inblk=1}
    inblk && $1=="mark" && $2 ~ re {print $2; exit}
    inblk && /^$/ {inblk=0}
  ' | head -n1)"

  [[ -n "${m:-}" ]] || return 0
  m="${m%%/*}"
  if [[ "$m" =~ ^0x ]]; then echo $((16#${m#0x})); else echo "$m"; fi
}

xfrm_reqid_from_state() {
  local mh hx re reqid
  mh="$(mark_hex_from_conf)"
  hx="${mh#0x}"
  re="^0x0*${hx}/0xffffffff$"

  reqid="$(ip xfrm state 2>/dev/null | awk -v re="${re}" '
    $1=="src" {inblk=1}
    inblk && $1=="mark" && $2 ~ re {markok=1}
    inblk && markok && $1=="proto" && $2=="esp" {
      for(i=1;i<=NF;i++) if($i=="reqid") {print $(i+1); exit}
    }
    inblk && /^$/ {inblk=0; markok=0}
  ' | head -n1)"

  reqid="${reqid%%(*}"
  reqid="${reqid//[^0-9]/}"
  [[ -n "${reqid:-}" ]] || return 0
  echo "$reqid"
}

xfrm_policy_install_tunnel_ips() {
  local lip rip reqid mark_dec_effective
  lip="$(local_tun_ip)"
  rip="${TUN_REMOTE_IP}"

  mark_dec_effective="$(xfrm_state_mark_dec || true)"
  [[ -n "${mark_dec_effective:-}" ]] || mark_dec_effective="$(mark_to_dec "${MARK}")"

  reqid="$(xfrm_reqid_from_state || true)"
  [[ -n "${reqid:-}" ]] || reqid="1"

  ip xfrm policy delete src "${lip}/32" dst "${rip}/32" dir out mark "${mark_dec_effective}" mask 0xffffffff 2>/dev/null || true
  ip xfrm policy delete src "${rip}/32" dst "${lip}/32" dir in  mark "${mark_dec_effective}" mask 0xffffffff 2>/dev/null || true
  ip xfrm policy delete src "${lip}/32" dst "${rip}/32" dir fwd mark "${mark_dec_effective}" mask 0xffffffff 2>/dev/null || true
  ip xfrm policy delete src "${lip}/32" dst "${rip}/32" dir out 2>/dev/null || true
  ip xfrm policy delete src "${rip}/32" dst "${lip}/32" dir in  2>/dev/null || true
  ip xfrm policy delete src "${lip}/32" dst "${rip}/32" dir fwd 2>/dev/null || true

  ip xfrm policy add src "${lip}/32" dst "${rip}/32" dir out \
    mark "${mark_dec_effective}" mask 0xffffffff \
    tmpl src "${LOCAL_WAN_IP}"  dst "${REMOTE_WAN_IP}" proto esp reqid "${reqid}" mode tunnel 2>/dev/null || true

  ip xfrm policy add src "${rip}/32" dst "${lip}/32" dir in \
    mark "${mark_dec_effective}" mask 0xffffffff \
    tmpl src "${REMOTE_WAN_IP}" dst "${LOCAL_WAN_IP}" proto esp reqid "${reqid}" mode tunnel 2>/dev/null || true

  ip xfrm policy add src "${lip}/32" dst "${rip}/32" dir fwd \
    mark "${mark_dec_effective}" mask 0xffffffff \
    tmpl src "${LOCAL_WAN_IP}"  dst "${REMOTE_WAN_IP}" proto esp reqid "${reqid}" mode tunnel 2>/dev/null || true
}

start_ipsec_try() {
  ipsec rereadsecrets >/dev/null 2>&1 || true
  ipsec reload >/dev/null 2>&1 || true

  local i
  for i in $(seq 1 "${IPSEC_UP_TRIES}"); do
    log "ipsec up ${conn_name} (try ${i}/${IPSEC_UP_TRIES})..."
    if timeout "${IPSEC_UP_TIMEOUT}" ipsec up "${conn_name}"; then
      return 0
    fi
    warn "ipsec up failed (try ${i}). (duplicate CHILD_SA may be OK if SA already exists)"
    sleep 1
  done
  return 1
}

if xfrm_state_present; then
  log "XFRM state already present for MARK; reinstalling policies only."
  xfrm_policy_install_tunnel_ips
  exit 0
fi

start_ipsec_try || warn "ipsec up did not succeed; checking if XFRM state exists anyway..."

if ! wait_for_xfrm_state; then
  err "No XFRM state found for this MARK; tunnel not established."
  echo
  warn "ip xfrm state:"
  ip xfrm state 2>/dev/null || true
  echo
  warn "ipsec statusall (top):"
  timeout 8 ipsec statusall | sed -n '1,160p' || true
  exit 1
fi

log "Installing XFRM ping policies for tunnel endpoints..."
xfrm_policy_install_tunnel_ips

log "Ping test: ${TUN_REMOTE_IP}"
ping -c 3 -W 2 "${TUN_REMOTE_IP}" >/dev/null 2>&1 && log "Ping OK." || warn "Ping failed (check SA counters: ip -s xfrm state)."
EOF

  # -----------------------
  # ACTIVATE helper
  # - Does NOT run during create/edit
  # - Periodically tries to start the tunnel service
  # - If tunnel ping becomes OK, it stops the activation timer itself
  # -----------------------
  cat >"$ACTIVATE_HELPER" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="/etc/simple-ipsec"
TUNNELS_DIR="$APP_DIR/tunnels.d"

tun="${1:-}"
[[ -n "${tun}" ]] || { echo "Usage: simple-ipsec-activate <tunnel_name>" >&2; exit 2; }

CONF_FILE="$TUNNELS_DIR/${tun}.conf"
[[ -f "$CONF_FILE" ]] || exit 0
# shellcheck disable=SC1090
source "$CONF_FILE"

svc="simple-ipsec@${tun}.service"
timer="simple-ipsec-activate@${tun}.timer"

log()  { echo "[simple-ipsec-activate:${tun}] $*"; }
warn() { echo "[simple-ipsec-activate:${tun}][WARN] $*" >&2; }

# If already healthy, stop the activation timer.
if systemctl is-active --quiet "$svc" 2>/dev/null; then
  if ping -c 1 -W 1 "${TUN_REMOTE_IP}" >/dev/null 2>&1; then
    log "Tunnel healthy (service active, ping OK). Stopping activation timer."
    systemctl stop "$timer" >/dev/null 2>&1 || true
    systemctl disable "$timer" >/dev/null 2>&1 || true
    exit 0
  fi
fi

# Try start the service (peer may not be ready; service may fail; we reset-failed to allow retries)
log "Attempting to start tunnel service (peer may not be ready yet)..."
systemctl start "$svc" >/dev/null 2>&1 || true

# If service failed, reset so next retry isn't blocked
systemctl reset-failed "$svc" >/dev/null 2>&1 || true

# Re-check: if now healthy, stop timer
if systemctl is-active --quiet "$svc" 2>/dev/null; then
  if ping -c 1 -W 1 "${TUN_REMOTE_IP}" >/dev/null 2>&1; then
    log "Tunnel became healthy. Stopping activation timer."
    systemctl stop "$timer" >/dev/null 2>&1 || true
    systemctl disable "$timer" >/dev/null 2>&1 || true
    exit 0
  fi
fi

warn "Not healthy yet (will retry on next activation tick)."
exit 0
EOF

  # -----------------------
  # HEALTH helper
  # - Ensures service is active
  # - If ping fails: run fix policies (Force fix), to recover policy issues
  # -----------------------
  cat >"$HEALTH_HELPER" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="/etc/simple-ipsec"
TUNNELS_DIR="$APP_DIR/tunnels.d"

tun="${1:-}"
[[ -n "${tun}" ]] || { echo "Usage: simple-ipsec-health <tunnel_name>" >&2; exit 2; }

CONF_FILE="$TUNNELS_DIR/${tun}.conf"
[[ -f "$CONF_FILE" ]] || exit 0
# shellcheck disable=SC1090
source "$CONF_FILE"

svc="simple-ipsec@${tun}.service"
fix_helper="/usr/local/sbin/simple-ipsec-fix"

log()  { echo "[simple-ipsec-health:${tun}] $*"; }
warn() { echo "[simple-ipsec-health:${tun}][WARN] $*" >&2; }

# Per-tunnel lock (avoid race with activate/up/fix)
lock="/run/simple-ipsec-${tun}.lock"
mkdir -p /run 2>/dev/null || true
exec 9>"$lock"
flock -n 9 || { warn "Another operation is running for this tunnel; skipping this tick."; exit 0; }

# 1) If service is not active: start it and exit (NO FIX in same run)
if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
  warn "Service is not active; starting it (no fix on this tick)."
  systemctl start "$svc" >/dev/null 2>&1 || true
  systemctl reset-failed "$svc" >/dev/null 2>&1 || true
  exit 0
fi

# 2) Ping check (only if configured)
if [[ -n "${TUN_REMOTE_IP:-}" ]]; then
  if ping -c 1 -W 1 "${TUN_REMOTE_IP}" >/dev/null 2>&1; then
    log "Ping OK."
    exit 0
  fi

  warn "Ping FAILED while service active. Running force-fix policies..."
  if [[ -x "$fix_helper" ]]; then
    "$fix_helper" "$tun" >/dev/null 2>&1 || true
  else
    warn "simple-ipsec-fix not found; fallback restart service."
    systemctl restart "$svc" >/dev/null 2>&1 || true
    systemctl reset-failed "$svc" >/dev/null 2>&1 || true
  fi
fi

exit 0
EOF

  chmod +x "$UP_HELPER" "$DOWN_HELPER" "$FIX_HELPER" "$ACTIVATE_HELPER" "$HEALTH_HELPER" || true
  systemctl daemon-reload
}

enable_service() {
  local svc; svc="$(service_for "$1")"
  systemctl enable "$svc" >/dev/null 2>&1 || true
}

# New: enable & start timers
enable_activation_timer() {
  local tun="$1"
  systemctl enable --now "$(activate_timer_for "$tun")" >/dev/null 2>&1 || true
}

enable_health_timer() {
  local tun="$1"
  systemctl enable --now "$(health_timer_for "$tun")" >/dev/null 2>&1 || true
}

stop_disable_service() {
  local svc
  svc="$(service_for "$1")"

  systemctl stop "$svc" >/dev/null 2>&1 || true
  systemctl disable "$svc" >/dev/null 2>&1 || true
  systemctl reset-failed "$svc" >/dev/null 2>&1 || true
}

stop_disable_timers_for_tunnel() {
  local tun="$1"
  systemctl stop "$(activate_timer_for "$tun")" >/dev/null 2>&1 || true
  systemctl disable "$(activate_timer_for "$tun")" >/dev/null 2>&1 || true
  systemctl stop "$(health_timer_for "$tun")" >/dev/null 2>&1 || true
  systemctl disable "$(health_timer_for "$tun")" >/dev/null 2>&1 || true
  systemctl reset-failed "simple-ipsec-activate@${tun}.service" >/dev/null 2>&1 || true
  systemctl reset-failed "simple-ipsec-health@${tun}.service" >/dev/null 2>&1 || true
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
  write_conf "$tun"
  write_ipsec_conn_conf "$tun"
  write_ipsec_secrets_block "$tun"
  write_sysctl_persist

  # IMPORTANT CHANGE:
  # Do NOT start/restart simple-ipsec@... during create/edit.
  # Only enable it, then activation timer will attempt start when peer is ready.
  enable_service "$tun"

  # Always reload ipsec configs (safe)
  ipsec_reload_all

  # Enable timers:
  # - activation timer: tries to bring tunnel up later (peer readiness)
  # - health timer: keeps it alive and fixes policies when ping fails
  enable_activation_timer "$tun"
  enable_health_timer "$tun"

  log "Applied config. Activation/Health timers enabled for: $tun"
}

iptables_delete_all_marks_for_if() {
  local ifc="$1"
  local line
  while true; do
    line="$(
      iptables -t mangle -S OUTPUT 2>/dev/null |
        grep -E -- "^-A OUTPUT\b.*\b-o ${ifc}\b.*\b-j (MARK|CONNMARK)\b" |
        head -n1
    )"
    [[ -z "${line:-}" ]] && break
    iptables -t mangle ${line/-A /-D } 2>/dev/null || true
  done

  while true; do
    line="$(
      iptables -t mangle -S PREROUTING 2>/dev/null |
        grep -E -- "^-A PREROUTING\b.*\b-i ${ifc}\b.*\b-j (MARK|CONNMARK)\b" |
        head -n1
    )"
    [[ -z "${line:-}" ]] && break
    iptables -t mangle ${line/-A /-D } 2>/dev/null || true
  done

  while true; do
    line="$(
      iptables -t mangle -S POSTROUTING 2>/dev/null |
        grep -E -- "^-A POSTROUTING\b.*\b-o ${ifc}\b.*\b-j (MARK|CONNMARK)\b" |
        head -n1
    )"
    [[ -z "${line:-}" ]] && break
    iptables -t mangle ${line/-A /-D } 2>/dev/null || true
  done
}

delete_ip_rules_for_mark_table() {
  local mark_dec="$1"
  local table="$2"

  ip rule show | awk -v m="$mark_dec" -v t="$table" '
    $0 ~ ("fwmark " m) && $0 ~ (" lookup " t) {print $1}
  ' | sed 's/://' | while read -r pref; do
    ip rule del pref "$pref" 2>/dev/null || true
  done
}

delete_routes_for_if_in_table() {
  local ifc="$1"
  local table="$2"

  ip -4 route show table "$table" 2>/dev/null | awk -v dev="$ifc" '
    $0 ~ (" dev " dev) {print}
  ' | while read -r line; do
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

  # Stop timers first
  stop_disable_timers_for_tunnel "$tun"

  stop_disable_service "$tun"

  if [[ -x /usr/local/sbin/simple-ipsec-down ]]; then
    /usr/local/sbin/simple-ipsec-down "$tun" >/dev/null 2>&1 || true
  fi

  iptables_delete_all_marks_for_if "$ifc"

  if [[ -n "${mark_dec:-}" ]]; then
    delete_ip_rules_for_mark_table "$mark_dec" "$table"
  fi
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
  echo "Local/Remote ID:        $LOCAL_ID  <->  $REMOTE_ID"
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
  local svc mark_hex MARK_DEC hx
  svc="$(service_for "$tun")"

  if systemctl is-active --quiet "$svc"; then
    echo -e "Service: ${GRN}active${NC}"
  else
    echo -e "Service: ${RED}inactive${NC}"
  fi

  if ip link show "$TUN_NAME" >/dev/null 2>&1; then
    echo -e "Interface: ${GRN}present${NC} (${TUN_NAME})"
  else
    echo -e "Interface: ${RED}missing${NC} (${TUN_NAME})"
  fi

  MARK_DEC="$(mark_to_dec "$MARK")"
  mark_hex="$(printf "0x%x" "$MARK_DEC")"
  hx="${mark_hex#0x}"
  if ip xfrm state 2>/dev/null | grep -Eqi "mark 0x0*${hx}/0xffffffff"; then
    echo -e "XFRM state: ${GRN}present${NC} (by MARK)"
  else
    echo -e "XFRM state: ${RED}missing${NC} (by MARK)"
  fi

  if ping -c 1 -W 1 "$TUN_REMOTE_IP" >/dev/null 2>&1; then
    echo -e "Ping: ${GRN}OK${NC} (${TUN_REMOTE_IP})"
  else
    echo -e "Ping: ${RED}FAIL${NC} (${TUN_REMOTE_IP})"
  fi

  echo
  echo -e "${WHT}Service:${NC}"
  systemctl --no-pager --full status "$svc" || true
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
  ip -d link show "$TUN_NAME" 2>/dev/null || { warn "Interface '$TUN_NAME' not found (service may be down)."; }
  ip -4 addr show dev "$TUN_NAME" 2>/dev/null || true
  echo

  echo -e "${WHT}Counters:${NC}"
  ip -s link show "$TUN_NAME" 2>/dev/null || true
  echo

  echo -e "${WHT}IPsec status (top):${NC}"
  ipsec statusall | sed -n '1,90p' || true
  echo

  echo -e "${WHT}Ping remote tunnel IP:${NC} ${TUN_REMOTE_IP}"
  if ping -c 3 -W 2 "$TUN_REMOTE_IP" >/dev/null 2>&1; then
    ok "Ping OK."
  else
    warn "Ping failed. (Health-check will auto fix policies if needed.)"
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
      local svc mark_hex MARK_DEC hx
      svc="$(service_for "$t")"

      if systemctl is-active --quiet "$svc"; then
        echo -e "Service: ${GRN}active${NC}"
      else
        echo -e "Service: ${RED}inactive${NC}"
      fi

      if ip link show "$TUN_NAME" >/dev/null 2>&1; then
        echo -e "Interface: ${GRN}present${NC} (${TUN_NAME})"
      else
        echo -e "Interface: ${RED}missing${NC} (${TUN_NAME})"
      fi

      MARK_DEC="$(mark_to_dec "$MARK")"
      mark_hex="$(printf "0x%x" "$MARK_DEC")"
      hx="${mark_hex#0x}"
      if ip xfrm state 2>/dev/null | grep -Eqi "mark 0x0*${hx}/0xffffffff"; then
        echo -e "XFRM state: ${GRN}present${NC} (by MARK)"
      else
        echo -e "XFRM state: ${RED}missing${NC} (by MARK)"
      fi

      if ping -c 1 -W 1 "$TUN_REMOTE_IP" >/dev/null 2>&1; then
        echo -e "Tunnel: ${GRN}active${NC} (ping OK)"
      else
        echo -e "Tunnel: ${RED}inactive${NC} (ping failed)"
      fi

      echo "Tunnel IP: ${TUN_LOCAL_CIDR} -> ${TUN_REMOTE_IP}"
      echo "IDs: ${LOCAL_ID} <-> ${REMOTE_ID}"
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
  LOCAL_ID=""; REMOTE_ID=""

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
  warn "Note: service is NOT started immediately. Activation timer will start it when peer is ready."
  echo
  echo -e "${GRN}Tunnel addressing:${NC}"
  echo "  PAIR_CODE:         ${PAIR_CODE}"
  echo "  Local CIDR:        ${TUN_LOCAL_CIDR}"
  echo "  Remote tunnel IP:  ${TUN_REMOTE_IP}"
  echo "  IDs:              ${LOCAL_ID} <-> ${REMOTE_ID}"
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
    # IMPORTANT: do not start/stop inline; just stop service to avoid using old settings mid-edit
    with_lock stop_disable_service "$old_tun" >/dev/null 2>&1 || true
    with_lock stop_disable_timers_for_tunnel "$old_tun" >/dev/null 2>&1 || true
  fi

  with_lock apply_tunnel_files_and_service "$TUN_NAME"

  ok "Tunnel updated & applied: ${TUN_NAME}"
  warn "Note: service is NOT started immediately. Activation timer will start it when peer is ready."
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
    echo -e "${CYA}6)${NC} Fix policies (one tunnel)"
    echo -e "${CYA}7)${NC} Fix policies (ALL tunnels)"
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
  write_sysctl_persist
  menu
}

main "$@"
