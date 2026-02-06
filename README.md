# Simple IPsec Tunnel (IKEv2 + VTI) — Multi Tunnel Manager

**Simple IPsec Tunnel** is a menu-driven Bash tool to create and manage **multiple IPsec (IKEv2) tunnels** using **VTI** (route-based) on Debian/Ubuntu (systemd).

It is designed to feel like a **Simple GRE** workflow:
- You get a **real interface** (`vti0`, `vti1`, ...)
- You get a **local /30 tunnel IP** derived from a **PAIR CODE (10.X.Y)**:
  - Local: `10.X.Y.1/30`
  - Remote: `10.X.Y.2/30`
- You can create/edit/delete tunnels safely (even multiple tunnels to the same peer)
- You get a **COPY BLOCK** to paste on the other server

---

## Features

- ✅ Multi tunnel (multiple VTI interfaces)
- ✅ Menu actions:
  - Create
  - Edit (rename supported)
  - Status (one)
  - Status (ALL)
  - Info + COPY BLOCK
  - List
  - Delete
  - **Force fix policies (one / all)** ✅
- ✅ Per tunnel configs:
  - `/etc/simple-ipsec/tunnels.d/<TUN_NAME>.conf`
- ✅ Per tunnel strongSwan connection:
  - `/etc/ipsec.d/simple-ipsec/<TUN_NAME>.conf`
- ✅ Per tunnel secrets block (safe multi-tunnel to same peer):
  - `/etc/ipsec.d/simple-ipsec.secrets`
- ✅ systemd template service per tunnel:
  - `simple-ipsec@<TUN_NAME>.service`
- ✅ Persists sysctl (recommended for VTI):
  - `ip_forward`
  - `rp_filter=0` (global + per tunnel interface)

---

## What “Force fix policies” does (Ping fix)

Sometimes a tunnel becomes **UP** but **ping over the tunnel IP does not pass** because **XFRM policies** (out/in/fwd) are not fully installed/applied.

This project includes a **Force fix** option that:
1. Tries `ipsec up <TUN_NAME>` (best-effort)
2. Waits for the `ip xfrm state` to appear (handles timing/race)
3. Re-applies **XFRM policies** for **OUT / IN / FWD** using the tunnel mark
4. Runs a quick ping test to verify

You can run it from the menu:
- **Force fix policies (one tunnel)**
- **Force fix policies (ALL tunnels)**

---

## Requirements

- Debian / Ubuntu
- Root access
- Public IPv4 on both servers
- UDP ports **500** and **4500** reachable between servers (IKE / NAT-T)

---

## Install & Run

Run on **each server**.

### Option A — Install from GitHub (online)
```bash
curl -fsSL https://raw.githubusercontent.com/ach1992/simple-ipsec-tunnel/main/install.sh | sudo bash
sudo simple-ipsec
```

### Option B — Local install (offline)
If you have `install.sh` and `ipsec_manager.sh` in the same folder:
```bash
sudo bash install.sh
sudo simple-ipsec
```

> In local mode, the installer will use the **local `ipsec_manager.sh`** (instead of downloading it).

---

## Recommended Workflow (Source ↔ Destination)

### 1) On Source server
1. Create tunnel
2. Copy the **COPY BLOCK**

### 2) On Destination server
1. Create tunnel
2. Paste the **COPY BLOCK**
3. Press **Enter twice** to finish paste

---

## Verify

From Source:
```bash
ping -c 3 10.X.Y.2
```

From Destination:
```bash
ping -c 3 10.X.Y.1
```

If ping fails but the tunnel is UP, run:
- Menu → **Force fix policies (one tunnel)** (or **ALL**)

Useful commands:
```bash
ip -d link show vti0
ip -4 addr show dev vti0
ip -s link show vti0
ip xfrm state
ip xfrm policy
ipsec statusall
systemctl status simple-ipsec@vti0.service --no-pager
```

---

## Notes

- This project creates the VTI interface and IPsec connection only.
- It does not automatically configure NAT or extra routes for other subnets.
- If you need routing of other subnets, add routes manually (or extend the script).

---

## License

MIT
