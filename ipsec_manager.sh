#!/usr/bin/env bash
set -Eeuo pipefail

# =========================
#  Simple IPsec Tunnel - IPsec VTI Manager (Multi Tunnel)
#  Repo: https://github.com/ach1992/simple-ipsec-tunnel
# =========================
# Debian/Ubuntu friendly (systemd)
# Features:
# - Create/Edit/Status/Info/Delete MULTIPLE IPsec(VTI) tunnels
# - Per-tunnel configs in /etc/simple-ipsec/tunnels.d/<tun>.conf
# - systemd template: simple-ipsec@<tun>.service
# - Route-based IPsec with VTI interface (gives you /30 local IP like GRE)
# - COPY BLOCK output per tunnel
# - Persists sysctl: ip_forward + rp_filter off (recommended for VTI/IPsec)
#
# Notes:
# - Requires UDP/500 and UDP/4500 reachable (IKE/NAT-T)
# - Uses strongSwan (ipsec/strongswan-starter)

APP_DIR="/etc/simple-ipsec"
TUNNELS_DIR="$APP_DIR/tunnels.d"
SYSCTL_FILE="$APP_DIR/99-simple-ipsec.conf"

IPSEC_INCLUDE_DIR="/etc/ipsec.d/simple-ipsec"
IPSEC_INCLUDE_CONF="/etc/ipsec.conf"
IPSEC_INCLUDE_SECRETS="/etc/ipsec.secrets"

SERVICE_TEMPLATE_FILE="/etc/systemd/system/simple-ipsec@.service"

REPO_URL="https://github.com/ach1992/simple-ipsec-tunnel"
APP_NAME="Simple IPsec Tunnel"

# Defaults
TUN_NAME_DEFAULT="vti0"
MARK_DEFAULT_MIN=10
MARK_DEFAULT_MAX=999999
MTU_DEFAULT="1436" # safe default for IPsec over UDP; adjust if needed
ENABLE_FORWARDING_DEFAULT="yes"
DISABLE_RPFILTER_DEFAULT="yes"

# Colors
RED="\033[0;31m"; GRN="\033[0;32m"; YEL="\033[0;33m"; BLU="\033[0;34m"
MAG="\033[0;35m"; CYA="\033[0;36m"; WHT="\033[1;37m"; NC="\033[0m"

log()   { echo -e "${BLU}[INFO]${NC} $*"; }
ok()    { echo -e "${GRN}[OK]${NC} $*"; }
warn()  { echo -e "${YEL}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*"; }
pause() { read -r -p "Press Enter to continue..." _; }

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    err "This script must be run as root."
    exit 1
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

require_cmds() {
  local missing=()
  for c in ip awk sed grep sysctl systemctl ping; do
    have_cmd "$c" || missing+=("$c")
  done
  if ! have_cmd ipsec; then
    missing+=("strongswan (ipsec)")
  fi
  if ((${#missing[@]})); then
    err "Missing required commands: ${missing[*]}"
    err "Install on Debian/Ubuntu:"
    err "  apt-get update && apt-get install -y strongswan iproute2 iputils-ping"
    exit 1
  fi
}

ensure_dirs() {
  mkdir -p "$APP_DIR" "$TUNNELS_DIR" "$IPSEC_INCLUDE_DIR"
  chmod 700 "$APP_DIR" "$TUNNELS_DIR" || true
  chmod 700 "$IPSEC_INCLUDE_DIR" || true
}

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

default_iface() {
  ip route 2>/dev/null | awk '/^default/{print $5; exit}'
}

get_iface_ip() {
  local iface="$1"
  ip -4 -o addr show dev "$iface" 2>/dev/null | awk '{print $4}' | head -n1 | cut -d/ -f1
}

conf_path_for() {
  local tun="$1"
  echo "$TUNNELS_DIR/${tun}.conf"
}

service_for() {
  local tun="$1"
  echo "simple-ipsec@${tun}.service"
}

conn_name_for() {
  local tun="$1"
  echo "simple-ipsec-${tun}"
}

ipsec_conn_conf_for() {
  local tun="$1"
  echo "$IPSEC_INCLUDE_DIR/${tun}.conf"
}

# -------------------------
# Name auto-pick (vtiN)
# -------------------------
name_taken() {
  local tun="$1"
  [[ -f "$(conf_path_for "$tun")" ]] && return 0
  ip link show "$tun" >/dev/null 2>&1 && return 0
  return 1
}

find_first_free_vti_name() {
  local base="${1:-vti}"
  local i=0
  local cand
  while true; do
    cand="${base}${i}"
    if ! name_taken "$cand"; then
      echo "$cand"
      return 0
    fi
    i=$((i+1))
    if (( i > 4096 )); then
      return 1
    fi
  done
}

# -------------------------
# PAIR CODE (10.X.Y) -> /30
# -------------------------
generate_pair_code() {
  local rx ry
  rx=$(( (RANDOM % 254) + 1 ))
  ry=$(( (RANDOM % 254) + 1 ))
  echo "10.${rx}.${ry}"
}

parse_pair_code() {
  local pc="$1"
  if [[ ! "$pc" =~ ^10\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
    return 1
  fi
  local x="${BASH_REMATCH[1]}" y="${BASH_REMATCH[2]}"
  [[ "$x" =~ ^[0-9]+$ && "$y" =~ ^[0-9]+$ ]] || return 1
  (( x >= 0 && x <= 255 && y >= 0 && y <= 255 )) || return 1
  echo "$x $y"
}

recompute_tunnel_ips_from_pair() {
  local parsed rx ry
  parsed="$(parse_pair_code "${PAIR_CODE}")" || { err "PAIR_CODE is invalid."; return 1; }
  rx="${parsed% *}"; ry="${parsed#* }"

  if [[ "${ROLE}" == "source" ]]; then
    TUN_LOCAL_CIDR="10.${rx}.${ry}.1/30"
    TUN_REMOTE_IP="10.${rx}.${ry}.2"
  else
    TUN_LOCAL_CIDR="10.${rx}.${ry}.2/30"
    TUN_REMOTE_IP="10.${rx}.${ry}.1"
  fi
  return 0
}

# -------------------------
# COPY BLOCK
# -------------------------
print_copy_block() {
  local src_ip dst_ip
  if [[ "${ROLE}" == "source" ]]; then
    src_ip="${LOCAL_WAN_IP}"
    dst_ip="${REMOTE_WAN_IP}"
  else
    src_ip="${REMOTE_WAN_IP}"
    dst_ip="${LOCAL_WAN_IP}"
  fi

  echo "----- SIMPLE_IPSEC_COPY_BLOCK -----"
  echo "PAIR_CODE=${PAIR_CODE}"
  echo "SOURCE_PUBLIC_IP=${src_ip}"
  echo "DEST_PUBLIC_IP=${dst_ip}"
  echo "TUN_NAME=${TUN_NAME}"
  echo "MARK=${MARK}"
  echo "MTU=${MTU}"
  echo "ENABLE_FORWARDING=${ENABLE_FORWARDING}"
  echo "DISABLE_RPFILTER=${DISABLE_RPFILTER}"
  echo "PSK=${PSK}"
  echo "----- END_COPY_BLOCK -----"
}

prompt_paste_copy_block() {
  echo -e "${CYA}Optional:${NC} Paste COPY BLOCK now (press Enter to skip)."
  echo -e "Finish paste by pressing ${WHT}Enter TWICE${NC} on empty lines."
  echo

  local first=""
  read -r -p "Paste first line (or just Enter to skip): " first || true
  if [[ -z "${first:-}" ]]; then
    return 0
  fi

  local lines=()
  lines+=("$first")

  local empty_count=0
  while true; do
    local line=""
    read -r line || true

    if [[ -z "${line:-}" ]]; then
      empty_count=$((empty_count + 1))
      if (( empty_count >= 2 )); then
        break
      fi
      continue
    fi

    empty_count=0
    lines+=("$line")
  done

  local kv key val
  for kv in "${lines[@]}"; do
    [[ "$kv" =~ ^[A-Z0-9_]+= ]] || continue
    key="${kv%%=*}"
    val="${kv#*=}"
    case "$key" in
      PAIR_CODE) PAIR_CODE="$val" ;;
      SOURCE_PUBLIC_IP) PASTE_SOURCE_PUBLIC_IP="$val" ;;
      DEST_PUBLIC_IP)   PASTE_DEST_PUBLIC_IP="$val" ;;
      TUN_NAME) TUN_NAME="$val" ;;
      MARK) MARK="$val" ;;
      MTU) MTU="$val" ;;
      ENABLE_FORWARDING) ENABLE_FORWARDING="$val" ;;
      DISABLE_RPFILTER)  DISABLE_RPFILTER="$val" ;;
      PSK) PSK="$val" ;;
      *) : ;;
    esac
  done

  if [[ -n "${PAIR_CODE:-}" ]] && ! parse_pair_code "$PAIR_CODE" >/dev/null; then
    err "Pasted PAIR_CODE is invalid."
    return 1
  fi
  if [[ -n "${PASTE_SOURCE_PUBLIC_IP:-}" ]] && ! is_ipv4 "$PASTE_SOURCE_PUBLIC_IP"; then
    err "Pasted SOURCE_PUBLIC_IP is invalid."
    return 1
  fi
  if [[ -n "${PASTE_DEST_PUBLIC_IP:-}" ]] && ! is_ipv4 "$PASTE_DEST_PUBLIC_IP"; then
    err "Pasted DEST_PUBLIC_IP is invalid."
    return 1
  fi
  if [[ -n "${TUN_NAME:-}" ]] && ! is_ifname "$TUN_NAME"; then
    err "Pasted TUN_NAME is invalid."
    return 1
  fi
  if [[ -n "${MARK:-}" ]]; then
    [[ "$MARK" =~ ^[0-9]+$ ]] || { err "Pasted MARK must be numeric."; return 1; }
    (( MARK >= 1 && MARK <= 2147483647 )) || { err "Pasted MARK out of range."; return 1; }
  fi
  if [[ -n "${MTU:-}" ]]; then
    [[ "$MTU" =~ ^[0-9]+$ ]] || { err "Pasted MTU must be numeric."; return 1; }
    (( MTU >= 1200 && MTU <= 9000 )) || { err "Pasted MTU out of range."; return 1; }
  fi
  if [[ -n "${ENABLE_FORWARDING:-}" ]] && [[ "$ENABLE_FORWARDING" != "yes" && "$ENABLE_FORWARDING" != "no" ]]; then
    err "Pasted ENABLE_FORWARDING must be 'yes' or 'no'."
    return 1
  fi
  if [[ -n "${DISABLE_RPFILTER:-}" ]] && [[ "$DISABLE_RPFILTER" != "yes" && "$DISABLE_RPFILTER" != "no" ]]; then
    err "Pasted DISABLE_RPFILTER must be 'yes' or 'no'."
    return 1
  fi
  if [[ -n "${PSK:-}" ]] && ((${#PSK} < 8)); then
    err "Pasted PSK looks too short."
    return 1
  fi

  ok "COPY BLOCK parsed successfully."
  return 0
}

# -------------------------
# Config I/O
# -------------------------
read_conf() {
  local tun="$1"
  local f
  f="$(conf_path_for "$tun")"
  [[ -f "$f" ]] || return 1
  # shellcheck disable=SC1090
  source "$f"
  return 0
}

write_conf() {
  local tun="$1"
  local f
  f="$(conf_path_for "$tun")"
  ensure_dirs
  cat >"$f" <<EOF
# Generated by simple-ipsec (multi tunnel)
ROLE="${ROLE}"
PAIR_CODE="${PAIR_CODE}"
TUN_NAME="${TUN_NAME}"
LOCAL_WAN_IP="${LOCAL_WAN_IP}"
REMOTE_WAN_IP="${REMOTE_WAN_IP}"
TUN_LOCAL_CIDR="${TUN_LOCAL_CIDR}"
TUN_REMOTE_IP="${TUN_REMOTE_IP}"
MARK="${MARK}"
MTU="${MTU}"
ENABLE_FORWARDING="${ENABLE_FORWARDING}"
DISABLE_RPFILTER="${DISABLE_RPFILTER}"
PSK="${PSK}"
EOF
  chmod 600 "$f"
}

list_tunnels() {
  ensure_dirs
  local f base
  shopt -s nullglob
  for f in "$TUNNELS_DIR"/*.conf; do
    base="$(basename "$f")"
    echo "${base%.conf}"
  done
  shopt -u nullglob
}

choose_tunnel() {
  local tunnels=()
  local t
  while IFS= read -r t; do
    [[ -n "$t" ]] && tunnels+=("$t")
  done < <(list_tunnels)

  if ((${#tunnels[@]} == 0)); then
    err "No tunnels found."
    return 1
  fi

  echo -e "${MAG}Available tunnels:${NC}"
  local i
  for i in "${!tunnels[@]}"; do
    printf "  %s) %s\n" "$((i+1))" "${tunnels[$i]}"
  done

  local choice
  while true; do
    read -r -p "Select tunnel [1-${#tunnels[@]}] (Enter=cancel): " choice || true
    if [[ -z "${choice:-}" ]]; then
      return 1
    fi
    if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#tunnels[@]} )); then
      SELECTED_TUN="${tunnels[$((choice-1))]}"
      return 0
    fi
    err "Invalid selection."
  done
}

# -------------------------
# Sysctl persist (global)
# -------------------------
compute_global_forwarding_needed() {
  local t need="no"
  while IFS= read -r t; do
    [[ -z "$t" ]] && continue
    if read_conf "$t"; then
      if [[ "${ENABLE_FORWARDING:-no}" == "yes" ]]; then
        need="yes"; break
      fi
    fi
  done < <(list_tunnels)
  echo "$need"
}

compute_rpfilter_needed() {
  local t need="no"
  while IFS= read -r t; do
    [[ -z "$t" ]] && continue
    if read_conf "$t"; then
      if [[ "${DISABLE_RPFILTER:-no}" == "yes" ]]; then
        need="yes"; break
      fi
    fi
  done < <(list_tunnels)
  echo "$need"
}

write_sysctl_persist() {
  ensure_dirs
  local forwarding_needed rp_needed
  forwarding_needed="$(compute_global_forwarding_needed)"
  rp_needed="$(compute_rpfilter_needed)"

  {
    echo "# Simple IPsec Tunnel sysctl (persist) - generated"
    echo "net.ipv4.ip_forward=$( [[ "$forwarding_needed" == "yes" ]] && echo 1 || echo 0 )"
    if [[ "$rp_needed" == "yes" ]]; then
      echo "net.ipv4.conf.all.rp_filter=0"
      echo "net.ipv4.conf.default.rp_filter=0"
      local t
      while IFS= read -r t; do
        [[ -z "$t" ]] && continue
        echo "net.ipv4.conf.${t}.rp_filter=0"
      done < <(list_tunnels)
    fi
  } >"$SYSCTL_FILE"

  chmod 644 "$SYSCTL_FILE"
  sysctl --system >/dev/null 2>&1 || true
}

# -------------------------
# Ensure strongSwan include hooks
# -------------------------
ensure_strongswan_includes() {
  ensure_dirs

  # ipsec.conf include
  if [[ -f "$IPSEC_INCLUDE_CONF" ]]; then
    if ! grep -qE '^\s*include\s+/etc/ipsec\.d/simple-ipsec/\*\.conf\s*$' "$IPSEC_INCLUDE_CONF"; then
      warn "Adding include to $IPSEC_INCLUDE_CONF"
      cp -a "$IPSEC_INCLUDE_CONF" "${IPSEC_INCLUDE_CONF}.bak.$(date +%s)" || true
      printf "\n# added by simple-ipsec\ninclude /etc/ipsec.d/simple-ipsec/*.conf\n" >> "$IPSEC_INCLUDE_CONF"
    fi
  else
    err "$IPSEC_INCLUDE_CONF not found. Is strongSwan installed correctly?"
    return 1
  fi

  # ipsec.secrets include
  if [[ -f "$IPSEC_INCLUDE_SECRETS" ]]; then
    if ! grep -qE '^\s*include\s+/etc/ipsec\.d/simple-ipsec\.secrets\s*$' "$IPSEC_INCLUDE_SECRETS"; then
      warn "Adding secrets include to $IPSEC_INCLUDE_SECRETS"
      cp -a "$IPSEC_INCLUDE_SECRETS" "${IPSEC_INCLUDE_SECRETS}.bak.$(date +%s)" || true
      printf "\n# added by simple-ipsec\ninclude /etc/ipsec.d/simple-ipsec.secrets\n" >> "$IPSEC_INCLUDE_SECRETS"
    fi
  else
    err "$IPSEC_INCLUDE_SECRETS not found."
    return 1
  fi

  # ensure secrets file exists
  touch /etc/ipsec.d/simple-ipsec.secrets
  chmod 600 /etc/ipsec.d/simple-ipsec.secrets
}

write_ipsec_conn_conf() {
  local tun="$1"
  local conn_name
  conn_name="$(conn_name_for "$tun")"

  cat >"$(ipsec_conn_conf_for "$tun")" <<EOF
# generated by simple-ipsec
conn ${conn_name}
  keyexchange=ikev2
  type=tunnel
  auto=start
  authby=psk

  left=${LOCAL_WAN_IP}
  right=${REMOTE_WAN_IP}

  # Route-based VTI: use mark + disable policy install
  mark=${MARK}
  installpolicy=no

  ike=aes256-sha256-modp2048!
  esp=aes256-sha256!

  dpdaction=restart
  dpddelay=30s
  keyingtries=%forever
EOF
  chmod 600 "$(ipsec_conn_conf_for "$tun")"
}

write_ipsec_secrets_line() {
  # store per-tunnel line in /etc/ipsec.d/simple-ipsec.secrets (idempotent by peer pair)
  local a="${LOCAL_WAN_IP}"
  local b="${REMOTE_WAN_IP}"
  local line="${a} ${b} : PSK \"${PSK}\""

  # remove any previous line for same peer pair (either direction)
  sed -i \
    -e "\|^${a}[[:space:]]+${b}[[:space:]]+: PSK |d" \
    -e "\|^${b}[[:space:]]+${a}[[:space:]]+: PSK |d" \
    /etc/ipsec.d/simple-ipsec.secrets

  echo "$line" >> /etc/ipsec.d/simple-ipsec.secrets
  chmod 600 /etc/ipsec.d/simple-ipsec.secrets
}

# -------------------------
# systemd template + up/down
# -------------------------
ensure_systemd_template() {
  cat >"$SERVICE_TEMPLATE_FILE" <<'EOF'
[Unit]
Description=Simple IPsec Tunnel - IPsec VTI (%i)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/simple-ipsec-up %i
ExecStop=/usr/local/sbin/simple-ipsec-down %i

[Install]
WantedBy=multi-user.target
EOF

  cat >/usr/local/sbin/simple-ipsec-up <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="/etc/simple-ipsec"
TUNNELS_DIR="$APP_DIR/tunnels.d"
SYSCTL_FILE="$APP_DIR/99-simple-ipsec.conf"

IPSEC_INCLUDE_DIR="/etc/ipsec.d/simple-ipsec"

tun="${1:-}"
[[ -n "${tun}" ]] || { echo "Usage: simple-ipsec-up <tunnel_name>" >&2; exit 2; }

CONF_FILE="$TUNNELS_DIR/${tun}.conf"
[[ -f "$CONF_FILE" ]] || { echo "Config not found: $CONF_FILE" >&2; exit 1; }
# shellcheck disable=SC1090
source "$CONF_FILE"

conn_name="simple-ipsec-${tun}"
conn_conf="${IPSEC_INCLUDE_DIR}/${tun}.conf"

apply_sysctl() {
  if [[ -f "$SYSCTL_FILE" ]]; then
    sysctl --system >/dev/null 2>&1 || true
  fi
  if [[ "${ENABLE_FORWARDING:-no}" == "yes" ]]; then
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
  fi
  if [[ "${DISABLE_RPFILTER:-no}" == "yes" ]]; then
    sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null 2>&1 || true
    sysctl -w "net.ipv4.conf.${TUN_NAME}.rp_filter=0" >/dev/null 2>&1 || true
  fi
}

ensure_vti() {
  if ! ip link show "${TUN_NAME}" >/dev/null 2>&1; then
    ip link add "${TUN_NAME}" type vti local "${LOCAL_WAN_IP}" remote "${REMOTE_WAN_IP}" key "${MARK}"
  fi
  ip link set "${TUN_NAME}" mtu "${MTU}" >/dev/null 2>&1 || true
  ip addr flush dev "${TUN_NAME}" >/dev/null 2>&1 || true
  ip addr add "${TUN_LOCAL_CIDR}" dev "${TUN_NAME}"
  ip link set "${TUN_NAME}" up
}

reload_ipsec() {
  # reread secrets + reload conns
  ipsec rereadsecrets >/dev/null 2>&1 || true
  ipsec reload >/dev/null 2>&1 || true

  # bring up this conn explicitly
  ipsec up "${conn_name}" >/dev/null 2>&1 || true
}

apply_sysctl
ensure_vti
reload_ipsec
EOF

  cat >/usr/local/sbin/simple-ipsec-down <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="/etc/simple-ipsec"
TUNNELS_DIR="$APP_DIR/tunnels.d"
IPSEC_INCLUDE_DIR="/etc/ipsec.d/simple-ipsec"

tun="${1:-}"
[[ -n "${tun}" ]] || { echo "Usage: simple-ipsec-down <tunnel_name>" >&2; exit 2; }

CONF_FILE="$TUNNELS_DIR/${tun}.conf"
[[ -f "$CONF_FILE" ]] || exit 0
# shellcheck disable=SC1090
source "$CONF_FILE"

conn_name="simple-ipsec-${tun}"

ipsec down "${conn_name}" >/dev/null 2>&1 || true

ip link set "${TUN_NAME}" down >/dev/null 2>&1 || true
ip link del "${TUN_NAME}" >/dev/null 2>&1 || true

# leave ipsec config files intact; manager handles delete.
EOF

  chmod +x /usr/local/sbin/simple-ipsec-up /usr/local/sbin/simple-ipsec-down
  systemctl daemon-reload
}

enable_service_for_tunnel() {
  local tun="$1"
  systemctl enable "simple-ipsec@${tun}.service" >/dev/null 2>&1 || true
}

apply_now_tunnel() {
  local tun="$1"
  systemctl restart "simple-ipsec@${tun}.service" >/dev/null 2>&1 || true
}

stop_disable_tunnel_service() {
  local tun="$1"
  systemctl stop "simple-ipsec@${tun}.service" >/dev/null 2>&1 || true
  systemctl disable "simple-ipsec@${tun}.service" >/dev/null 2>&1 || true
}

# -------------------------
# Prompts
# -------------------------
prompt_role() {
  echo "Select server role:"
  echo "  1) Source (Iran)"
  echo "  2) Destination (Kharej)"
  local choice
  while true; do
    read -r -p "Enter choice [1-2]: " choice || true
    case "${choice:-}" in
      1) ROLE="source"; break ;;
      2) ROLE="destination"; break ;;
      *) err "Invalid choice. Please enter 1 or 2." ;;
    esac
  done
}

prompt_tun_name_new() {
  local inp chosen
  read -r -p "VTI interface name [${TUN_NAME_DEFAULT}]: " inp || true
  inp="${inp:-$TUN_NAME_DEFAULT}"

  is_ifname "$inp" || { err "Invalid interface name."; return 1; }

  if ! name_taken "$inp"; then
    TUN_NAME="$inp"
    return 0
  fi

  if [[ "$inp" =~ ^vti[0-9]+$ ]] || [[ "$inp" == "vti" ]]; then
    chosen="$(find_first_free_vti_name "vti")" || { err "Could not find a free vtiN name."; return 1; }
    warn "Name '${inp}' is already taken. Auto-selected: ${chosen}"
    TUN_NAME="$chosen"
    return 0
  fi

  err "Name '${inp}' is already taken. Choose another."
  return 1
}

prompt_local_wan_ip() {
  local inp def_if def_ip
  def_if="$(default_iface || true)"
  def_ip=""
  if [[ -n "${def_if:-}" ]]; then
    def_ip="$(get_iface_ip "$def_if" || true)"
  fi

  if [[ -n "${LOCAL_WAN_IP:-}" ]]; then
    read -r -p "Local public IPv4 [${LOCAL_WAN_IP}]: " inp || true
    inp="${inp:-$LOCAL_WAN_IP}"
  elif [[ -n "${def_ip:-}" ]]; then
    read -r -p "Local public IPv4 (detected: ${def_ip}) [${def_ip}]: " inp || true
    inp="${inp:-$def_ip}"
  else
    read -r -p "Local public IPv4: " inp || true
  fi

  is_ipv4 "${inp:-}" || { err "Invalid IPv4."; return 1; }
  LOCAL_WAN_IP="$inp"
  return 0
}

prompt_remote_wan_ip() {
  local inp
  read -r -p "Remote public IPv4 [${REMOTE_WAN_IP:-}]: " inp || true
  inp="${inp:-${REMOTE_WAN_IP:-}}"
  is_ipv4 "${inp:-}" || { err "Invalid IPv4."; return 1; }
  REMOTE_WAN_IP="$inp"
  return 0
}

prompt_pair_code() {
  local inp
  if [[ -z "${PAIR_CODE:-}" ]]; then
    echo "PAIR CODE format: 10.X.Y"
    read -r -p "PAIR CODE [auto]: " inp || true
    if [[ -z "${inp:-}" ]]; then
      PAIR_CODE="$(generate_pair_code)"
      ok "Generated PAIR CODE: ${PAIR_CODE}"
      return 0
    fi
    parse_pair_code "$inp" >/dev/null || { err "Invalid PAIR CODE."; return 1; }
    PAIR_CODE="$inp"
    return 0
  fi

  read -r -p "PAIR CODE [${PAIR_CODE}] (Enter=keep): " inp || true
  inp="${inp:-$PAIR_CODE}"
  parse_pair_code "$inp" >/dev/null || { err "Invalid PAIR CODE."; return 1; }
  PAIR_CODE="$inp"
  return 0
}

prompt_mark() {
  local inp
  if [[ -z "${MARK:-}" ]]; then
    MARK=$(( (RANDOM % (MARK_DEFAULT_MAX - MARK_DEFAULT_MIN + 1)) + MARK_DEFAULT_MIN ))
    read -r -p "MARK (VTI key/mark) [${MARK}]: " inp || true
    inp="${inp:-$MARK}"
  else
    read -r -p "MARK (VTI key/mark) [${MARK}]: " inp || true
    inp="${inp:-$MARK}"
  fi
  [[ "$inp" =~ ^[0-9]+$ ]] && (( inp >= 1 && inp <= 2147483647 )) || { err "Invalid MARK."; return 1; }
  MARK="$inp"
}

prompt_mtu() {
  local inp
  read -r -p "MTU [${MTU}]: " inp || true
  inp="${inp:-$MTU}"
  [[ "$inp" =~ ^[0-9]+$ ]] && (( inp >= 1200 && inp <= 9000 )) || { err "Invalid MTU."; return 1; }
  MTU="$inp"
}

prompt_tuning() {
  local inp
  read -r -p "Enable IPv4 forwarding? [${ENABLE_FORWARDING}] (yes/no): " inp || true
  inp="${inp:-$ENABLE_FORWARDING}"
  [[ "$inp" == "yes" || "$inp" == "no" ]] || { err "Invalid value."; return 1; }
  ENABLE_FORWARDING="$inp"

  read -r -p "Disable rp_filter? [${DISABLE_RPFILTER}] (yes/no): " inp || true
  inp="${inp:-$DISABLE_RPFILTER}"
  [[ "$inp" == "yes" || "$inp" == "no" ]] || { err "Invalid value."; return 1; }
  DISABLE_RPFILTER="$inp"
}

prompt_psk() {
  local inp
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
    if [[ -n "${inp:-}" ]]; then
      PSK="$inp"
    fi
  fi

  ((${#PSK} >= 8)) || { err "PSK too short."; return 1; }
}

# -------------------------
# Actions
# -------------------------
do_list() {
  echo -e "${MAG}===== Tunnels =====${NC}"
  local found="no"
  local t
  while IFS= read -r t; do
    [[ -z "$t" ]] && continue
    found="yes"
    echo " - $t"
  done < <(list_tunnels)

  if [[ "$found" == "no" ]]; then
    warn "No tunnels configured yet."
  fi
}

show_info_one() {
  local tun="$1"
  if ! read_conf "$tun"; then
    err "No configuration found for: $tun"
    return
  fi

  echo -e "${MAG}===== IPsec(VTI) Configuration: ${tun} =====${NC}"
  echo "Role:                ${ROLE}"
  echo "Pair code:           ${PAIR_CODE}"
  echo "VTI name:            ${TUN_NAME}"
  echo "Local public IP:     ${LOCAL_WAN_IP}"
  echo "Remote public IP:    ${REMOTE_WAN_IP}"
  echo "Local tunnel CIDR:   ${TUN_LOCAL_CIDR}"
  echo "Remote tunnel IP:    ${TUN_REMOTE_IP}"
  echo "MARK:                ${MARK}"
  echo "MTU:                 ${MTU}"
  echo "IPv4 forwarding:     ${ENABLE_FORWARDING}"
  echo "rp_filter disabled:  ${DISABLE_RPFILTER}"
  echo "Config file:         $(conf_path_for "$tun")"
  echo "IPsec conn file:     $(ipsec_conn_conf_for "$tun")"
  echo

  echo -e "${CYA}COPY BLOCK (paste on the other server):${NC}"
  warn "COPY BLOCK includes PSK. Keep it private."
  print_copy_block
  echo -e "${YEL}Finish paste on the other server:${NC} Press Enter twice on empty lines."
}

do_create() {
  log "Creating NEW IPsec(VTI) tunnel..."
  echo

  prompt_role
  echo

  # Defaults
  TUN_NAME=""
  MTU="$MTU_DEFAULT"
  ENABLE_FORWARDING="$ENABLE_FORWARDING_DEFAULT"
  DISABLE_RPFILTER="$DISABLE_RPFILTER_DEFAULT"
  PAIR_CODE=""
  LOCAL_WAN_IP=""
  REMOTE_WAN_IP=""
  MARK=""
  PSK=""
  PASTE_SOURCE_PUBLIC_IP=""
  PASTE_DEST_PUBLIC_IP=""

  if ! prompt_paste_copy_block; then
    err "Failed to parse COPY BLOCK."
    return
  fi
  echo

  prompt_tun_name_new || return

  if [[ -n "${PASTE_SOURCE_PUBLIC_IP:-}" && -n "${PASTE_DEST_PUBLIC_IP:-}" ]]; then
    if [[ "${ROLE}" == "source" ]]; then
      LOCAL_WAN_IP="${PASTE_SOURCE_PUBLIC_IP}"
      REMOTE_WAN_IP="${PASTE_DEST_PUBLIC_IP}"
    else
      LOCAL_WAN_IP="${PASTE_DEST_PUBLIC_IP}"
      REMOTE_WAN_IP="${PASTE_SOURCE_PUBLIC_IP}"
    fi
    ok "Public IPs filled from COPY BLOCK."
  fi

  prompt_local_wan_ip || return
  prompt_remote_wan_ip || return
  prompt_pair_code || return
  recompute_tunnel_ips_from_pair || return

  prompt_mark || return
  prompt_mtu || return
  prompt_tuning || return
  prompt_psk || return

  ensure_systemd_template
  ensure_strongswan_includes

  write_conf "$TUN_NAME"
  write_sysctl_persist

  # write strongSwan conn + secrets
  write_ipsec_conn_conf "$TUN_NAME"
  write_ipsec_secrets_line

  enable_service_for_tunnel "$TUN_NAME"
  apply_now_tunnel "$TUN_NAME"

  ok "Tunnel '${TUN_NAME}' created and persisted (systemd)."
  echo
  echo -e "${GRN}Tunnel addressing:${NC}"
  echo "  PAIR CODE:          ${PAIR_CODE}"
  echo "  Local tunnel CIDR:  ${TUN_LOCAL_CIDR}"
  echo "  Remote tunnel IP:   ${TUN_REMOTE_IP}"
  echo
  echo -e "${CYA}COPY BLOCK (paste on the other server):${NC}"
  warn "COPY BLOCK includes PSK. Keep it private."
  print_copy_block
  echo -e "${YEL}Finish paste on the other server:${NC} Press Enter twice on empty lines."
}

do_status_one() {
  if ! choose_tunnel; then return; fi
  local tun="$SELECTED_TUN"
  if ! read_conf "$tun"; then err "No config for: $tun"; return; fi

  local conn
  conn="$(conn_name_for "$tun")"

  echo -e "${MAG}===== IPsec(VTI) Status: ${tun} =====${NC}"
  echo -e "${WHT}Service:${NC}"
  systemctl --no-pager --full status "$(service_for "$tun")" || true
  echo

  echo -e "${WHT}Interface:${NC}"
  ip -d link show "$TUN_NAME" 2>/dev/null || { err "Interface not found. Try restarting service."; return; }
  ip -d link show "$TUN_NAME" || true
  echo

  echo -e "${WHT}IP addresses:${NC}"
  ip -4 addr show dev "$TUN_NAME" || true
  echo

  echo -e "${WHT}Counters:${NC}"
  ip -s link show "$TUN_NAME" || true
  echo

  echo -e "${WHT}IPsec status:${NC}"
  ipsec statusall | sed -n '1,80p' || true
  echo

  echo -e "${WHT}Connectivity test:${NC} ping remote tunnel IP (${TUN_REMOTE_IP})"
  if ping -c 3 -W 2 "$TUN_REMOTE_IP" >/dev/null 2>&1; then
    ok "Ping successful. VTI looks reachable."
  else
    warn "Ping failed."
    warn "If IPsec is UP but ping fails: check MTU, rp_filter=0, and that both sides have matching PAIR_CODE/MARK/PSK."
  fi
}

do_info() {
  if ! choose_tunnel; then return; fi
  show_info_one "$SELECTED_TUN"
}

do_delete() {
  if ! choose_tunnel; then return; fi
  local tun="$SELECTED_TUN"
  if ! read_conf "$tun"; then err "No config for: $tun"; return; fi

  warn "This will remove tunnel '$tun', its systemd service, and IPsec conn file. Secrets line will be removed for this peer pair."
  local yn
  read -r -p "Are you sure? [y/N]: " yn || true
  yn="${yn:-N}"
  if [[ ! "$yn" =~ ^([yY])$ ]]; then
    log "Canceled."
    return
  fi

  stop_disable_tunnel_service "$tun"

  # remove interface
  ip link set "$TUN_NAME" down >/dev/null 2>&1 || true
  ip link del "$TUN_NAME" >/dev/null 2>&1 || true

  # remove ipsec conn conf
  rm -f "$(ipsec_conn_conf_for "$tun")" || true

  # remove secrets line (both directions)
  if [[ -f /etc/ipsec.d/simple-ipsec.secrets ]]; then
    sed -i \
      -e "\|^${LOCAL_WAN_IP}[[:space:]]+${REMOTE_WAN_IP}[[:space:]]+: PSK |d" \
      -e "\|^${REMOTE_WAN_IP}[[:space:]]+${LOCAL_WAN_IP}[[:space:]]+: PSK |d" \
      /etc/ipsec.d/simple-ipsec.secrets || true
  fi

  rm -f "$(conf_path_for "$tun")" || true

  write_sysctl_persist
  ipsec reload >/dev/null 2>&1 || true
  ipsec rereadsecrets >/dev/null 2>&1 || true

  ok "Deleted tunnel '$tun'."
}

banner() {
  echo -e "${MAG}========================================${NC}"
  echo -e "${WHT}  ${APP_NAME}${NC}  ${CYA}(IPsec VTI Manager - Multi)${NC}"
  echo -e "${YEL}  Repo:${NC} ${BLU}${REPO_URL}${NC}"
  echo -e "${MAG}========================================${NC}"
}

menu() {
  while true; do
    clear || true
    banner
    echo -e "${CYA}1)${NC} Create tunnel (new)"
    echo -e "${CYA}2)${NC} Status (one tunnel)"
    echo -e "${CYA}3)${NC} Info / COPY BLOCK (one tunnel)"
    echo -e "${CYA}4)${NC} List tunnels"
    echo -e "${CYA}5)${NC} Delete tunnel"
    echo -e "${CYA}0)${NC} Exit"
    echo -e "${MAG}----------------------------------------${NC}"
    local choice
    read -r -p "Select an option [0-5]: " choice || true
    case "${choice:-}" in
      1) do_create; pause ;;
      2) do_status_one; pause ;;
      3) do_info; pause ;;
      4) do_list; pause ;;
      5) do_delete; pause ;;
      0) exit 0 ;;
      *) err "Invalid selection."; pause ;;
    esac
  done
}

main() {
  require_root
  require_cmds
  ensure_dirs
  ensure_systemd_template
  ensure_strongswan_includes
  menu
}

main "$@"
