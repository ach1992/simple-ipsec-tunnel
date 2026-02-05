#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================================
# Simple IPsec Tunnel (IKEv2 + VTI) — Multi Tunnel Manager
# Repo: https://github.com/ach1992/simple-ipsec-tunnel
#
# Goals (GRE-like UX):
#  - Multi tunnel
#  - Create / Edit / Status / Status ALL / Info / List / Delete
#  - COPY BLOCK + Paste COPY BLOCK (finish paste with Enter twice)
#  - Local /30 tunnel IP derived from PAIR CODE (10.X.Y)
#  - Robust apply/remove; no hanging on IPsec up
#
# Tech:
#  - strongSwan (ipsec)
#  - Linux VTI: ip link add vtiX type vti ... key MARK
#  - Route-based data-plane hookup via fwmark + ip rule + mangle MARK
#
# Notes:
#  - We use installpolicy=no in IPsec conn and do policy routing ourselves.
#  - Data plane requires iptables (iptables-nft ok).
# ============================================================

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

APP_NAME="Simple IPsec Tunnel"
REPO_URL="https://github.com/ach1992/simple-ipsec-tunnel"

APP_DIR="/etc/simple-ipsec"
TUNNELS_DIR="$APP_DIR/tunnels.d"
SYSCTL_FILE="$APP_DIR/99-simple-ipsec.conf"

IPSEC_CONN_DIR="/etc/ipsec.d/simple-ipsec"
IPSEC_SECRETS_FILE="/etc/ipsec.d/simple-ipsec.secrets"
IPSEC_MAIN_CONF="/etc/ipsec.conf"

BIN_UP="/usr/local/sbin/simple-ipsec-up"
BIN_DOWN="/usr/local/sbin/simple-ipsec-down"
SYSTEMD_TEMPLATE="/etc/systemd/system/simple-ipsec@.service"

# ---------- colors ----------
RED="\033[0;31m"; GRN="\033[0;32m"; YEL="\033[0;33m"; BLU="\033[0;34m"; CYA="\033[0;36m"; WHT="\033[1;37m"; NC="\033[0m"

hr() { echo -e "${RED}------------------------------------------------------------${NC}"; }
ok() { echo -e "${GRN}[OK]${NC} $*"; }
info(){ echo -e "${BLU}[INFO]${NC} $*"; }
warn(){ echo -e "${YEL}[WARN]${NC} $*"; }
err(){ echo -e "${RED}[ERROR]${NC} $*"; }
pause(){ read -r -p "Press Enter to continue..." _ || true; }

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    err "Run as root (sudo)."
    exit 1
  fi
}

have_cmd(){ command -v "$1" >/dev/null 2>&1; }

require_cmds_or_fail() {
  local missing=()
  have_cmd ip || missing+=("iproute2 (ip)")
  have_cmd ping || missing+=("iputils-ping (ping)")
  have_cmd ipsec || missing+=("strongswan/strongswan-starter (ipsec)")
  have_cmd timeout || missing+=("coreutils (timeout)")
  have_cmd iptables || missing+=("iptables")
  if ((${#missing[@]} > 0)); then
    err "Missing required commands: ${missing[*]}"
    echo -e "${YEL}Debian/Ubuntu install:${NC}"
    echo "  apt-get update && apt-get install -y strongswan strongswan-starter iproute2 iputils-ping coreutils iptables"
    exit 1
  fi
}

mkdirs() {
  mkdir -p "$APP_DIR" "$TUNNELS_DIR" "$IPSEC_CONN_DIR"
  chmod 700 "$APP_DIR" "$TUNNELS_DIR" || true
}

# ---------- helpers ----------
service_for(){ echo "simple-ipsec@$1.service"; }
conn_name_for(){ echo "simple-ipsec-$1"; }
tunnel_conf_for(){ echo "$TUNNELS_DIR/$1.conf"; }
ipsec_conn_conf_for(){ echo "$IPSEC_CONN_DIR/$1.conf"; }

list_tunnels() {
  ls -1 "$TUNNELS_DIR" 2>/dev/null | sed -n 's/\.conf$//p' | sort || true
}

tunnel_exists() {
  [[ -f "$(tunnel_conf_for "$1")" ]]
}

detect_public_ipv4() {
  # best-effort: pick src of default route
  ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}'
}

rand_mark() {
  # 20000-60000
  echo $(( 20000 + (RANDOM % 40001) ))
}

rand_pair_code() {
  # 10.X.Y where X,Y in 1..254
  local x y
  x=$(( 1 + (RANDOM % 254) ))
  y=$(( 1 + (RANDOM % 254) ))
  echo "10.$x.$y"
}

pair_code_in_use() {
  local code="$1"
  local f
  for f in "$TUNNELS_DIR"/*.conf; do
    [[ -f "$f" ]] || continue
    # shellcheck disable=SC1090
    source "$f" 2>/dev/null || true
    if [[ "${PAIR_CODE:-}" == "$code" ]]; then
      return 0
    fi
  done
  return 1
}

generate_unique_pair_code() {
  local code
  for _ in $(seq 1 50); do
    code="$(rand_pair_code)"
    if ! pair_code_in_use "$code"; then
      echo "$code"
      return 0
    fi
  done
  # fallback even if collision
  echo "$(rand_pair_code)"
}

gen_psk() {
  # 32 chars url-safe
  tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c 32 || echo "psk$(date +%s)"
}

read_default() {
  local prompt="$1" default="$2" var
  read -r -p "$prompt [$default]: " var || true
  if [[ -z "${var:-}" ]]; then
    echo "$default"
  else
    echo "$var"
  fi
}

read_yesno() {
  local prompt="$1" default="$2" v
  while true; do
    read -r -p "$prompt [$default] (yes/no, Enter=keep): " v || true
    v="${v:-$default}"
    case "$v" in
      yes|no) echo "$v"; return 0 ;;
      *) echo "Please type yes or no." ;;
    esac
  done
}

# ---------- IPsec include + secrets ----------
ensure_ipsec_include() {
  # ensure /etc/ipsec.conf includes our directory
  if [[ ! -f "$IPSEC_MAIN_CONF" ]]; then
    warn "$IPSEC_MAIN_CONF not found. strongSwan may use different layout on this system."
    return 0
  fi

  if ! grep -qE "include\s+$IPSEC_CONN_DIR/\*\.conf" "$IPSEC_MAIN_CONF"; then
    info "Ensuring ipsec.conf includes $IPSEC_CONN_DIR/*.conf"
    # append near end
    {
      echo ""
      echo "# added by simple-ipsec"
      echo "include $IPSEC_CONN_DIR/*.conf"
    } >>"$IPSEC_MAIN_CONF"
  fi
}

secrets_block_begin(){ echo "# BEGIN simple-ipsec $1"; }
secrets_block_end(){ echo "# END simple-ipsec $1"; }

upsert_secrets_block() {
  local tun="$1" left="$2" right="$3" psk="$4"
  mkdir -p "$(dirname "$IPSEC_SECRETS_FILE")"
  touch "$IPSEC_SECRETS_FILE"
  chmod 600 "$IPSEC_SECRETS_FILE" || true

  local begin end tmp
  begin="$(secrets_block_begin "$tun")"
  end="$(secrets_block_end "$tun")"
  tmp="$(mktemp)"

  # remove old block
  awk -v b="$begin" -v e="$end" '
    $0==b {skip=1; next}
    $0==e {skip=0; next}
    skip!=1 {print}
  ' "$IPSEC_SECRETS_FILE" >"$tmp"

  {
    echo "$begin"
    echo "${left} ${right} : PSK \"${psk}\""
    echo "$end"
  } >>"$tmp"

  cat "$tmp" >"$IPSEC_SECRETS_FILE"
  rm -f "$tmp"
}

remove_secrets_block() {
  local tun="$1"
  [[ -f "$IPSEC_SECRETS_FILE" ]] || return 0
  local begin end tmp
  begin="$(secrets_block_begin "$tun")"
  end="$(secrets_block_end "$tun")"
  tmp="$(mktemp)"
  awk -v b="$begin" -v e="$end" '
    $0==b {skip=1; next}
    $0==e {skip=0; next}
    skip!=1 {print}
  ' "$IPSEC_SECRETS_FILE" >"$tmp"
  cat "$tmp" >"$IPSEC_SECRETS_FILE"
  rm -f "$tmp"
}

# ---------- sysctl ----------
write_sysctl_persist() {
  local content tmp
  tmp="$(mktemp)"
  {
    echo "# generated by simple-ipsec"
    echo "net.ipv4.ip_forward=1"
    echo "net.ipv4.conf.all.rp_filter=0"
    echo "net.ipv4.conf.default.rp_filter=0"
  } >"$tmp"

  local t
  while read -r t; do
    [[ -n "$t" ]] || continue
    echo "net.ipv4.conf.${t}.rp_filter=0" >>"$tmp"
    echo "net.ipv4.conf.${t}.disable_policy=1" >>"$tmp"
    echo "net.ipv4.conf.${t}.disable_xfrm=0" >>"$tmp"
  done < <(list_tunnels)

  mkdir -p "$APP_DIR"
  cat "$tmp" >"$SYSCTL_FILE"
  rm -f "$tmp"

  # link into sysctl.d for persistence
  mkdir -p /etc/sysctl.d
  ln -sf "$SYSCTL_FILE" "/etc/sysctl.d/99-simple-ipsec.conf"

  sysctl -p "/etc/sysctl.d/99-simple-ipsec.conf" >/dev/null 2>&1 || true
}

# ---------- write IPsec conn conf ----------
write_ipsec_conn_conf() {
  local tun="$1"
  local conn_name
  conn_name="$(conn_name_for "$tun")"

  # shellcheck disable=SC2154
  cat >"$(ipsec_conn_conf_for "$tun")" <<EOF
# generated by simple-ipsec
conn ${conn_name}
  keyexchange=ikev2
  type=tunnel
  auto=start
  authby=psk

  left=${LOCAL_WAN_IP}
  right=${REMOTE_WAN_IP}

  # We handle policy routing ourselves (fwmark + ip rule + mangle MARK)
  mark=${MARK}
  installpolicy=no

  # Allow traffic selectors (we will decide routes)
  leftsubnet=0.0.0.0/0
  rightsubnet=0.0.0.0/0

  ike=aes256-sha256-modp2048!
  esp=aes256-sha256!

  dpdaction=restart
  dpddelay=30s
  keyingtries=%forever
EOF

  chmod 600 "$(ipsec_conn_conf_for "$tun")" || true
}

# ---------- write tunnel conf ----------
write_tunnel_conf() {
  local tun="$1"
  local f
  f="$(tunnel_conf_for "$tun")"
  cat >"$f" <<EOF
# generated by simple-ipsec
TUN_NAME=${tun}
CONN_NAME=$(conn_name_for "$tun")

LOCAL_WAN_IP=${LOCAL_WAN_IP}
REMOTE_WAN_IP=${REMOTE_WAN_IP}

PAIR_CODE=${PAIR_CODE}
LOCAL_SUFFIX=${LOCAL_SUFFIX}
REMOTE_SUFFIX=${REMOTE_SUFFIX}

TUN_LOCAL_IP=${TUN_LOCAL_IP}
TUN_REMOTE_IP=${TUN_REMOTE_IP}
TUN_LOCAL_CIDR=${TUN_LOCAL_CIDR}
TUN_NET_CIDR=${TUN_NET_CIDR}

MARK=${MARK}
MTU=${MTU}

ENABLE_FORWARDING=${ENABLE_FORWARDING}
DISABLE_RPFILTER=${DISABLE_RPFILTER}

PSK=${PSK}
EOF
  chmod 600 "$f" || true
}

load_tunnel_conf() {
  local tun="$1" f
  f="$(tunnel_conf_for "$tun")"
  if [[ ! -f "$f" ]]; then
    err "Tunnel config not found: $f"
    return 1
  fi
  # shellcheck disable=SC1090
  source "$f"
  return 0
}

recalc_ips_from_pair() {
  # uses PAIR_CODE + LOCAL_SUFFIX/REMOTE_SUFFIX
  local base="$PAIR_CODE"
  TUN_LOCAL_IP="${base}.${LOCAL_SUFFIX}"
  TUN_REMOTE_IP="${base}.${REMOTE_SUFFIX}"
  TUN_LOCAL_CIDR="${TUN_LOCAL_IP}/30"
  # network base /30:
  local net="${base}.0/30"
  TUN_NET_CIDR="$net"
}

# ---------- systemd + helper scripts ----------
ensure_systemd_template() {
  if [[ -f "$SYSTEMD_TEMPLATE" ]]; then
    return 0
  fi

  info "Creating systemd template: $SYSTEMD_TEMPLATE"
  cat >"$SYSTEMD_TEMPLATE" <<'EOF'
[Unit]
Description=Simple IPsec Tunnel - IPsec VTI (%i)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes

# Anti-hang: never wait forever
TimeoutStartSec=15
TimeoutStopSec=10

ExecStart=/usr/local/sbin/simple-ipsec-up %i
ExecStop=/usr/local/sbin/simple-ipsec-down %i

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload >/dev/null 2>&1 || true
}

ensure_helpers() {
  # FULL REPLACE helper scripts with our stable versions
  info "Ensuring helper scripts exist..."

  cat >"$BIN_UP" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

TUN_NAME="${1:-}"
if [[ -z "${TUN_NAME}" ]]; then
  echo "[ERROR] Missing tunnel name (e.g. vti0)"
  exit 1
fi

CONF_FILE="/etc/simple-ipsec/tunnels.d/${TUN_NAME}.conf"
if [[ ! -f "${CONF_FILE}" ]]; then
  echo "[ERROR] Tunnel config not found: ${CONF_FILE}"
  exit 1
fi

# shellcheck disable=SC1090
source "${CONF_FILE}"

log(){ echo "[simple-ipsec-up:${TUN_NAME}] $*"; }
require_cmd(){ command -v "$1" >/dev/null 2>&1 || { log "[ERROR] missing cmd: $1"; exit 1; }; }

require_cmd ip
require_cmd ipsec
require_cmd sysctl
require_cmd iptables
require_cmd timeout

CONN_NAME="${CONN_NAME:-simple-ipsec-${TUN_NAME}}"

apply_sysctl_runtime() {
  if [[ "${ENABLE_FORWARDING:-yes}" == "yes" ]]; then
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
  fi
  if [[ "${DISABLE_RPFILTER:-yes}" == "yes" ]]; then
    sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null 2>&1 || true
    sysctl -w "net.ipv4.conf.${TUN_NAME}.rp_filter=0" >/dev/null 2>&1 || true
  fi
}

ensure_vti() {
  dotted_to_dec() { awk -F. '{print ($1*16777216)+($2*65536)+($3*256)+$4}'; }
  local need_recreate="no"
  local cur_ikey_dotted=""

  if ip link show "${TUN_NAME}" >/dev/null 2>&1; then
    cur_ikey_dotted="$(ip -d link show "${TUN_NAME}" 2>/dev/null | awk '
      {for(i=1;i<=NF;i++) if($i=="ikey"){print $(i+1); exit}}
    ')"
    if [[ -n "${cur_ikey_dotted:-}" ]]; then
      local cur_ikey_dec
      cur_ikey_dec="$(echo "${cur_ikey_dotted}" | dotted_to_dec)"
      if [[ "${cur_ikey_dec:-}" != "${MARK}" ]]; then
        need_recreate="yes"
      fi
    else
      need_recreate="yes"
    fi
  else
    need_recreate="yes"
  fi

  if [[ "${need_recreate}" == "yes" ]]; then
    ip link del "${TUN_NAME}" >/dev/null 2>&1 || true
    ip link add "${TUN_NAME}" type vti local "${LOCAL_WAN_IP}" remote "${REMOTE_WAN_IP}" key "${MARK}"
  fi

  ip link set "${TUN_NAME}" mtu "${MTU}" >/dev/null 2>&1 || true
  ip addr flush dev "${TUN_NAME}" >/dev/null 2>&1 || true
  ip addr add "${TUN_LOCAL_CIDR}" dev "${TUN_NAME}"
  ip link set "${TUN_NAME}" up

  # stabilize VTI behavior across kernels
  sysctl -w "net.ipv4.conf.${TUN_NAME}.disable_policy=1" >/dev/null 2>&1 || true
  sysctl -w "net.ipv4.conf.${TUN_NAME}.disable_xfrm=0"   >/dev/null 2>&1 || true
}

setup_policy_routing() {
  # table per mark (multi-tunnel friendly)
  local table_id
  table_id=$(( 1000 + (MARK % 1000) ))

  # rule: fwmark -> table
  ip rule del fwmark "${MARK}" table "${table_id}" 2>/dev/null || true
  ip rule add fwmark "${MARK}" table "${table_id}" priority 1000

  # routes in that table
  ip route flush table "${table_id}" >/dev/null 2>&1 || true
  ip route add "${TUN_REMOTE_IP}/32" dev "${TUN_NAME}" table "${table_id}" 2>/dev/null || true
  ip route add "${TUN_NET_CIDR}" dev "${TUN_NAME}" table "${table_id}" 2>/dev/null || true

  # mark traffic that egresses vti
  iptables -t mangle -D OUTPUT -o "${TUN_NAME}" -j MARK --set-mark "${MARK}" 2>/dev/null || true
  iptables -t mangle -A OUTPUT -o "${TUN_NAME}" -j MARK --set-mark "${MARK}"

  # mark traffic that arrives from vti (best-effort)
  iptables -t mangle -D PREROUTING -i "${TUN_NAME}" -j MARK --set-mark "${MARK}" 2>/dev/null || true
  iptables -t mangle -A PREROUTING -i "${TUN_NAME}" -j MARK --set-mark "${MARK}"
}

start_ipsec() {
  ipsec rereadsecrets >/dev/null 2>&1 || true
  ipsec reload >/dev/null 2>&1 || true

  # avoid accumulating SAs
  ipsec down "${CONN_NAME}" >/dev/null 2>&1 || true
  timeout 12 ipsec up "${CONN_NAME}" >/dev/null 2>&1 || true
}

main() {
  apply_sysctl_runtime
  ensure_vti
  setup_policy_routing
  start_ipsec
  log "UP done."
}

main "$@"
EOF

  cat >"$BIN_DOWN" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

TUN_NAME="${1:-}"
if [[ -z "${TUN_NAME}" ]]; then
  echo "[ERROR] Missing tunnel name (e.g. vti0)"
  exit 1
fi

CONF_FILE="/etc/simple-ipsec/tunnels.d/${TUN_NAME}.conf"
if [[ ! -f "${CONF_FILE}" ]]; then
  echo "[ERROR] Tunnel config not found: ${CONF_FILE}"
  exit 1
fi

# shellcheck disable=SC1090
source "${CONF_FILE}"

log(){ echo "[simple-ipsec-down:${TUN_NAME}] $*"; }
require_cmd(){ command -v "$1" >/dev/null 2>&1 || { log "[ERROR] missing cmd: $1"; exit 1; }; }

require_cmd ip
require_cmd ipsec
require_cmd iptables

CONN_NAME="${CONN_NAME:-simple-ipsec-${TUN_NAME}}"

cleanup_policy_routing() {
  local table_id
  table_id=$(( 1000 + (MARK % 1000) ))

  ip rule del fwmark "${MARK}" table "${table_id}" 2>/dev/null || true
  ip route flush table "${table_id}" >/dev/null 2>&1 || true

  iptables -t mangle -D OUTPUT -o "${TUN_NAME}" -j MARK --set-mark "${MARK}" 2>/dev/null || true
  iptables -t mangle -D PREROUTING -i "${TUN_NAME}" -j MARK --set-mark "${MARK}" 2>/dev/null || true
}

stop_ipsec() {
  ipsec down "${CONN_NAME}" >/dev/null 2>&1 || true
}

delete_vti() {
  ip link del "${TUN_NAME}" >/dev/null 2>&1 || true
}

main() {
  cleanup_policy_routing
  stop_ipsec
  delete_vti
  log "DOWN done."
}

main "$@"
EOF

  chmod 755 "$BIN_UP" "$BIN_DOWN" || true
}

# ---------- apply / remove ----------
restart_service_safe() {
  local tun="$1"
  local svc
  svc="$(service_for "$tun")"

  systemctl enable "$svc" >/dev/null 2>&1 || true
  # Anti-hang guard (systemd has TimeoutStartSec too)
  timeout 15 systemctl restart "$svc" >/dev/null 2>&1 || true
}

stop_disable_service() {
  local tun="$1"
  local svc
  svc="$(service_for "$tun")"
  timeout 10 systemctl stop "$svc" >/dev/null 2>&1 || true
  systemctl disable "$svc" >/dev/null 2>&1 || true
}

apply_tunnel() {
  local tun="$1"
  load_tunnel_conf "$tun" >/dev/null

  ensure_ipsec_include
  ensure_helpers
  ensure_systemd_template

  # write IPsec conn + secrets (based on loaded variables)
  write_ipsec_conn_conf "$tun"
  upsert_secrets_block "$tun" "$LOCAL_WAN_IP" "$REMOTE_WAN_IP" "$PSK"

  # persist sysctl for all tunnels
  write_sysctl_persist

  restart_service_safe "$tun"

  ok "Tunnel applied: $tun"
}

remove_tunnel_artifacts() {
  local tun="$1"
  stop_disable_service "$tun"
  timeout 5 "$BIN_DOWN" "$tun" >/dev/null 2>&1 || true

  rm -f "$(tunnel_conf_for "$tun")" >/dev/null 2>&1 || true
  rm -f "$(ipsec_conn_conf_for "$tun")" >/dev/null 2>&1 || true
  remove_secrets_block "$tun"

  write_sysctl_persist

  ok "Removed tunnel: $tun"
}

# ---------- COPY BLOCK ----------
print_copy_block() {
  local tun="$1"
  load_tunnel_conf "$tun" >/dev/null

  hr
  echo -e "${WHT}COPY BLOCK (paste on the other server)${NC}"
  hr
  cat <<EOF
BEGIN_COPY_BLOCK
LOCAL_PUBLIC_IP=${LOCAL_WAN_IP}
REMOTE_PUBLIC_IP=${REMOTE_WAN_IP}
TUN_NAME=${TUN_NAME}
PAIR_CODE=${PAIR_CODE}
LOCAL_SUFFIX=${LOCAL_SUFFIX}
MARK=${MARK}
MTU=${MTU}
ENABLE_FORWARDING=${ENABLE_FORWARDING}
DISABLE_RPFILTER=${DISABLE_RPFILTER}
PSK=${PSK}
END_COPY_BLOCK
EOF
  hr
}

prompt_paste_copy_block() {
  echo -e "${CYA}Optional:${NC} Paste COPY BLOCK now (press Enter to skip)."
  echo -e "Finish paste by pressing ${WHT}Enter twice${NC} on empty lines."
  echo

  local first=""
  echo -e "${YEL}Paste the COPY BLOCK now.${NC}"
  echo -e "When you're done, press ${WHT}Enter twice${NC} on empty lines to finish."
  echo
  read -r -p "Paste first line (or just Enter to skip): " first || true
  [[ -n "${first:-}" ]] || return 0

  local lines=("$first") empty_count=0 line=""
  while true; do
    line=""
    read -r line || true
    if [[ -z "${line:-}" ]]; then
      empty_count=$((empty_count+1))
      if (( empty_count >= 2 )); then
        echo
        ok "Paste finished (Enter twice detected). Parsing COPY BLOCK..."
        echo
        break
      fi
      continue
    fi
    empty_count=0
    lines+=("$line")
  done

  # parse key=val lines
  local kv key val
  for kv in "${lines[@]}"; do
    case "$kv" in
      BEGIN_COPY_BLOCK|END_COPY_BLOCK) continue ;;
    esac
    key="${kv%%=*}"
    val="${kv#*=}"
    key="$(echo "$key" | tr -d '[:space:]')"
    val="$(echo "$val" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    case "$key" in
      LOCAL_PUBLIC_IP) P_LOCAL_PUBLIC_IP="$val" ;;
      REMOTE_PUBLIC_IP) P_REMOTE_PUBLIC_IP="$val" ;;
      TUN_NAME) P_TUN_NAME="$val" ;;
      PAIR_CODE) P_PAIR_CODE="$val" ;;
      LOCAL_SUFFIX) P_LOCAL_SUFFIX="$val" ;;
      MARK) P_MARK="$val" ;;
      MTU) P_MTU="$val" ;;
      ENABLE_FORWARDING) P_ENABLE_FORWARDING="$val" ;;
      DISABLE_RPFILTER) P_DISABLE_RPFILTER="$val" ;;
      PSK) P_PSK="$val" ;;
    esac
  done

  # validate minimum
  if [[ -z "${P_LOCAL_PUBLIC_IP:-}" || -z "${P_REMOTE_PUBLIC_IP:-}" || -z "${P_TUN_NAME:-}" || -z "${P_PAIR_CODE:-}" || -z "${P_MARK:-}" || -z "${P_PSK:-}" ]]; then
    warn "COPY BLOCK incomplete. Skipping paste import."
    return 0
  fi

  # Apply swap logic: other side local=REMOTE_PUBLIC_IP, remote=LOCAL_PUBLIC_IP
  LOCAL_WAN_IP="${P_REMOTE_PUBLIC_IP}"
  REMOTE_WAN_IP="${P_LOCAL_PUBLIC_IP}"
  TUN_NAME="${P_TUN_NAME}"
  PAIR_CODE="${P_PAIR_CODE}"
  MARK="${P_MARK}"
  MTU="${P_MTU:-1436}"
  ENABLE_FORWARDING="${P_ENABLE_FORWARDING:-yes}"
  DISABLE_RPFILTER="${P_DISABLE_RPFILTER:-yes}"
  PSK="${P_PSK}"

  # suffix flip: if pasted block had local suffix 1 => we are 2, and vice versa
  if [[ "${P_LOCAL_SUFFIX:-1}" == "1" ]]; then
    LOCAL_SUFFIX="2"; REMOTE_SUFFIX="1"
  else
    LOCAL_SUFFIX="1"; REMOTE_SUFFIX="2"
  fi
  recalc_ips_from_pair

  ok "COPY BLOCK parsed."
  return 0
}

# ---------- menu actions ----------
pick_tunnel() {
  local arr=() t i=1 sel
  while read -r t; do
    [[ -n "$t" ]] || continue
    arr+=("$t")
  done < <(list_tunnels)

  if ((${#arr[@]} == 0)); then
    warn "No tunnels found."
    return 1
  fi

  echo
  echo "Available tunnels:"
  for t in "${arr[@]}"; do
    echo "  [$i] $t"
    i=$((i+1))
  done
  echo
  read -r -p "Select tunnel number: " sel || true
  [[ "$sel" =~ ^[0-9]+$ ]] || return 1
  (( sel>=1 && sel<=${#arr[@]} )) || return 1
  echo "${arr[$((sel-1))]}"
}

create_tunnel() {
  hr
  echo -e "${WHT}Create new tunnel${NC}"
  hr

  # optional paste
  P_LOCAL_PUBLIC_IP=""; P_REMOTE_PUBLIC_IP=""; P_TUN_NAME=""; P_PAIR_CODE=""; P_LOCAL_SUFFIX=""
  P_MARK=""; P_MTU=""; P_ENABLE_FORWARDING=""; P_DISABLE_RPFILTER=""; P_PSK=""
  prompt_paste_copy_block || true

  # defaults
  local detected_ip
  detected_ip="$(detect_public_ipv4 || true)"
  detected_ip="${detected_ip:-}"

  # if pasted, variables already set (LOCAL_WAN_IP etc). If not, ask.
  TUN_NAME="${TUN_NAME:-vti0}"

  TUN_NAME="$(read_default "VTI interface name" "$TUN_NAME")"
  if [[ ! "$TUN_NAME" =~ ^vti[0-9]+$ ]]; then
    warn "Recommended naming: vti0, vti1, ..."
  fi
  if tunnel_exists "$TUN_NAME"; then
    err "Tunnel already exists: $TUN_NAME"
    pause
    return
  fi

  if [[ -z "${LOCAL_WAN_IP:-}" ]]; then
    LOCAL_WAN_IP="$(read_default "Local public IPv4 (detected: ${detected_ip:-N/A})" "${detected_ip:-}")"
  else
    echo -e "Local public IPv4 (from COPY BLOCK): ${WHT}${LOCAL_WAN_IP}${NC}"
  fi

  if [[ -z "${REMOTE_WAN_IP:-}" ]]; then
    REMOTE_WAN_IP="$(read_default "Remote public IPv4" "")"
  else
    echo -e "Remote public IPv4 (from COPY BLOCK): ${WHT}${REMOTE_WAN_IP}${NC}"
  fi

  if [[ -z "${PAIR_CODE:-}" ]]; then
    PAIR_CODE="$(generate_unique_pair_code)"
    echo -e "PAIR CODE (format: 10.X.Y) [auto]:"
    echo -e "${ok} Generated PAIR CODE: ${WHT}${PAIR_CODE}${NC}"
  else
    echo -e "PAIR CODE (from COPY BLOCK): ${WHT}${PAIR_CODE}${NC}"
  fi

  if [[ -z "${LOCAL_SUFFIX:-}" ]]; then
    # choose role (source=1, dest=2)
    local role
    role="$(read_default "Local tunnel side (1=.1, 2=.2)" "1")"
    if [[ "$role" == "2" ]]; then
      LOCAL_SUFFIX="2"; REMOTE_SUFFIX="1"
    else
      LOCAL_SUFFIX="1"; REMOTE_SUFFIX="2"
    fi
    recalc_ips_from_pair
  else
    echo -e "Local tunnel IP will be: ${WHT}${TUN_LOCAL_CIDR}${NC} (remote ${TUN_REMOTE_IP})"
  fi

  MARK="${MARK:-$(rand_mark)}"
  MARK="$(read_default "MARK (VTI key/mark)" "$MARK")"

  MTU="${MTU:-1436}"
  MTU="$(read_default "MTU" "$MTU")"

  ENABLE_FORWARDING="${ENABLE_FORWARDING:-yes}"
  ENABLE_FORWARDING="$(read_yesno "Enable IPv4 forwarding?" "$ENABLE_FORWARDING")"

  DISABLE_RPFILTER="${DISABLE_RPFILTER:-yes}"
  DISABLE_RPFILTER="$(read_yesno "Disable rp_filter?" "$DISABLE_RPFILTER")"

  if [[ -z "${PSK:-}" ]]; then
    PSK="$(gen_psk)"
    ok "Generated PSK."
  else
    ok "PSK from COPY BLOCK loaded."
  fi

  write_tunnel_conf "$TUN_NAME"
  apply_tunnel "$TUN_NAME"

  echo
  print_copy_block "$TUN_NAME"
  pause
}

edit_tunnel() {
  hr
  echo -e "${WHT}Edit tunnel${NC}"
  hr
  local tun
  tun="$(pick_tunnel)" || { pause; return; }

  load_tunnel_conf "$tun" >/dev/null

  echo
  echo -e "Editing: ${WHT}${tun}${NC}"
  echo "1) Rename tunnel"
  echo "2) Change Public IPs"
  echo "3) Change PAIR CODE (recalc /30)"
  echo "4) Change MARK (VTI key/mark)"
  echo "5) Change MTU"
  echo "6) Regenerate PSK"
  echo "7) Toggle forwarding / rp_filter"
  echo "0) Back"
  echo
  local c
  read -r -p "Select: " c || true

  case "$c" in
    1)
      local new
      new="$(read_default "New tunnel name" "$tun")"
      if [[ "$new" == "$tun" ]]; then
        ok "No change."
      else
        if tunnel_exists "$new"; then
          err "Target name already exists: $new"
          pause; return
        fi
        # stop old service
        stop_disable_service "$tun"
        timeout 5 "$BIN_DOWN" "$tun" >/dev/null 2>&1 || true

        # rename files
        mv "$(tunnel_conf_for "$tun")" "$(tunnel_conf_for "$new")"
        rm -f "$(ipsec_conn_conf_for "$tun")" >/dev/null 2>&1 || true
        remove_secrets_block "$tun"

        # update in conf
        TUN_NAME="$new"
        write_tunnel_conf "$new"
        apply_tunnel "$new"
        ok "Renamed $tun -> $new"
      fi
      ;;
    2)
      LOCAL_WAN_IP="$(read_default "Local public IPv4" "$LOCAL_WAN_IP")"
      REMOTE_WAN_IP="$(read_default "Remote public IPv4" "$REMOTE_WAN_IP")"
      write_tunnel_conf "$tun"
      apply_tunnel "$tun"
      ;;
    3)
      PAIR_CODE="$(read_default "PAIR CODE (10.X.Y)" "$PAIR_CODE")"
      # keep same side suffix
      LOCAL_SUFFIX="${LOCAL_SUFFIX:-1}"
      if [[ "$LOCAL_SUFFIX" == "1" ]]; then REMOTE_SUFFIX="2"; else REMOTE_SUFFIX="1"; fi
      recalc_ips_from_pair
      write_tunnel_conf "$tun"
      apply_tunnel "$tun"
      ;;
    4)
      MARK="$(read_default "MARK" "$MARK")"
      write_tunnel_conf "$tun"
      apply_tunnel "$tun"
      ;;
    5)
      MTU="$(read_default "MTU" "$MTU")"
      write_tunnel_conf "$tun"
      apply_tunnel "$tun"
      ;;
    6)
      PSK="$(gen_psk)"
      ok "Generated new PSK."
      write_tunnel_conf "$tun"
      apply_tunnel "$tun"
      ;;
    7)
      ENABLE_FORWARDING="$(read_yesno "Enable IPv4 forwarding?" "$ENABLE_FORWARDING")"
      DISABLE_RPFILTER="$(read_yesno "Disable rp_filter?" "$DISABLE_RPFILTER")"
      write_tunnel_conf "$tun"
      apply_tunnel "$tun"
      ;;
    *) ;;
  esac

  pause
}

status_one() {
  hr
  echo -e "${WHT}Tunnel status${NC}"
  hr
  local tun
  tun="$(pick_tunnel)" || { pause; return; }
  load_tunnel_conf "$tun" >/dev/null

  echo
  echo -e "${CYA}Interface:${NC}"
  ip -d link show "$tun" 2>/dev/null || echo "(no interface)"
  ip -4 addr show dev "$tun" 2>/dev/null || true
  echo
  echo -e "${CYA}Counters:${NC}"
  ip -s link show "$tun" 2>/dev/null || true

  echo
  echo -e "${CYA}IPsec status (top):${NC}"
  ipsec statusall 2>/dev/null | sed -n '1,180p' || true

  echo
  echo -e "${CYA}Connectivity test:${NC} ping remote tunnel IP (${TUN_REMOTE_IP})"
  timeout 3 ping -c 2 -I "$tun" "$TUN_REMOTE_IP" >/dev/null 2>&1 && ok "Ping OK." || warn "Ping failed. Check: same PAIR_CODE/MARK/PSK on both sides, MTU, rp_filter=0, and IPsec is UP."
  pause
}

status_all() {
  hr
  echo -e "${WHT}Status ALL tunnels${NC}"
  hr
  local t
  while read -r t; do
    [[ -n "$t" ]] || continue
    load_tunnel_conf "$t" >/dev/null || continue
    echo
    echo -e "${WHT}== $t ==${NC}"
    ip -4 addr show dev "$t" 2>/dev/null | sed 's/^/  /' || echo "  (no interface)"
    echo -e "  PAIR: ${PAIR_CODE}  local ${TUN_LOCAL_IP}  remote ${TUN_REMOTE_IP}  MARK ${MARK}"
    # show bytes line if exists
    ipsec statusall 2>/dev/null | grep -E "$(conn_name_for "$t")|bytes_i|bytes_o|INSTALLED|ESTABLISHED" | head -n 6 | sed 's/^/  /' || true
  done < <(list_tunnels)
  pause
}

info_one() {
  hr
  echo -e "${WHT}Tunnel info${NC}"
  hr
  local tun
  tun="$(pick_tunnel)" || { pause; return; }
  load_tunnel_conf "$tun" >/dev/null

  echo
  echo -e "Name: ${WHT}${tun}${NC}"
  echo "Local public:  $LOCAL_WAN_IP"
  echo "Remote public: $REMOTE_WAN_IP"
  echo "PAIR CODE:     $PAIR_CODE"
  echo "Tunnel local:  $TUN_LOCAL_CIDR"
  echo "Tunnel remote: $TUN_REMOTE_IP"
  echo "MARK:          $MARK"
  echo "MTU:           $MTU"
  echo "Forwarding:    $ENABLE_FORWARDING"
  echo "rp_filter off: $DISABLE_RPFILTER"
  echo
  print_copy_block "$tun"
  pause
}

list_action() {
  hr
  echo -e "${WHT}List tunnels${NC}"
  hr
  list_tunnels || true
  pause
}

delete_tunnel() {
  hr
  echo -e "${WHT}Delete tunnel${NC}"
  hr
  local tun
  tun="$(pick_tunnel)" || { pause; return; }

  read -r -p "Type DELETE to confirm removing $tun: " cf || true
  if [[ "$cf" != "DELETE" ]]; then
    warn "Cancelled."
    pause
    return
  fi

  remove_tunnel_artifacts "$tun"
  pause
}

menu() {
  clear || true
  echo -e "${WHT}${APP_NAME}${NC}"
  echo -e "${BLU}${REPO_URL}${NC}"
  hr
  echo "1) Create tunnel"
  echo "2) Edit tunnel"
  echo "3) Status (one)"
  echo "4) Status (ALL)"
  echo "5) Info + COPY BLOCK"
  echo "6) List tunnels"
  echo "7) Delete tunnel"
  echo "0) Exit"
  hr
}

main() {
  need_root
  mkdirs
  require_cmds_or_fail

  while true; do
    menu
    local opt
    read -r -p "Select an option [0-7]: " opt || true
    case "$opt" in
      1) create_tunnel ;;
      2) edit_tunnel ;;
      3) status_one ;;
      4) status_all ;;
      5) info_one ;;
      6) list_action ;;
      7) delete_tunnel ;;
      0) exit 0 ;;
      *) ;;
    esac
  done
}

main "$@"
