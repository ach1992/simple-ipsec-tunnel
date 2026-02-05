# Simple IPsec Tunnel — IPsec VTI Manager (Multi Tunnel)

A simple **menu-driven** Bash tool to create and manage **multiple IPsec (IKEv2) tunnels** using **VTI** (route-based) on Debian/Ubuntu (systemd).

This gives you a **local /30 tunnel IP** (like GRE), e.g.:
- Iran: 10.X.Y.1/30
- Kharej: 10.X.Y.2/30

---

## Features

- ✅ Multi tunnel on one server
- ✅ Per-tunnel configs:
  - `/etc/simple-ipsec/tunnels.d/<TUN_NAME>.conf`
- ✅ systemd template service per tunnel:
  - `simple-ipsec@<TUN_NAME>.service`
- ✅ Auto generates `PAIR_CODE (10.X.Y)` and assigns `/30`
- ✅ Generates **COPY BLOCK** (paste on the other server)
- ✅ Auto manages strongSwan includes:
  - `/etc/ipsec.d/simple-ipsec/*.conf`
  - `/etc/ipsec.d/simple-ipsec.secrets`
- ✅ Persists sysctl:
  - `ip_forward` and `rp_filter=0` (recommended)

---

## Requirements

- Debian / Ubuntu
- Root access
- Public IPv4 on both servers
- UDP ports **500** and **4500** reachable between servers (IKE/NAT-T)

---

## Install & Run

Run on **each server**:

```bash
curl -fsSL https://raw.githubusercontent.com/ach1992/simple-ipsec-tunnel/main/install.sh | sudo bash
sudo simple-ipsec
```

---

## Recommended Workflow (Iran ↔ Kharej)

### 1) On Iran server (Source)
- Create tunnel
- Copy the generated **COPY BLOCK**

### 2) On Kharej server (Destination)
- Create tunnel
- Paste the COPY BLOCK
- Press **Enter twice** to finish paste

---

## Verify

From Iran:
```bash
ping -c 3 10.X.Y.2
```

From Kharej:
```bash
ping -c 3 10.X.Y.1
```

Useful:
```bash
ip -d link show vti0
ip -4 addr show dev vti0
ip -s link show vti0
ipsec statusall
systemctl status simple-ipsec@vti0.service --no-pager
```

---

## Notes

- This project creates the VTI interface and IPsec connection only.
- It does not automatically configure NAT or extra routes for other subnets.
- If you need routing of other subnets, add routes manually (or we can extend the project later).

---

## License
MIT
