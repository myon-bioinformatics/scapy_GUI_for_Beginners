# Scapy L2/L3 Toolkit

A single-window GUI to learn and test L2/L3 networking with Scapy. 

One place for ICMP/TCP/UDP basics, DNS (UDP/TCP/DoT), ARP scan, traceroute, PCAP sending, a FastAPI+Uvicorn helper server, UDP echo, realtime sniffing, and environment/network info popups.

- **GUI**: FreeSimpleGUI (preferred) / PySimpleGUI v4 (fallback)
- **HTTP helper**: FastAPI + Uvicorn
- **OS**: Windows / macOS / Linux (raw sockets usually need **admin/root**)

> ⚠️ Use only in permitted environments. Scans and active tests may be regulated by law or internal policy.

---

## Table of Contents

1. [Features](#features)  
1. [Requirements](#requirements)  
1. [Installation](#installation)  
1. [Run](#run)  
1. [Basic Usage](#basic-usage)   
1. [Popups (Env/Versions & Network)](#popups-envversions--network)  
1. [Troubleshooting](#troubleshooting)  
1. [Screenshots](#screenshots)  
1. [License](#license)  
1. [Credits](#credits)

---

## Features

- 🇯🇵/🇬🇧 UI toggle (Japanese/English)
- Endpoints (src/dst/TTL/timeout/retries)
- **Ping 1/2-way**, **SYN 1/3-way**, **TCP scan**
- **DNS sender** (UDP/TCP/DoT)  
  - EDNS0 / DO / NSID / EDE (subset)
- **ARP scan**
- **Traceroute** (ICMP/UDP/TCP, parallel TTL, PTR lookup)
- **PCAP sender** (IP rewrite; send/sendp; sendpfast via `tcpreplay`)
- **Custom payload sender** (ICMP/TCP/UDP/RAW)
- **Local HTTP server** (FastAPI + Uvicorn)  
  - `/healthz`, `/echo`, `/time`, `/static/*` (when docroot is set)
- **UDP Echo server**
- **Realtime sniffer** (PPS sparkline, protocol ratio, rolling PCAP, CSV)
- **Env/Versions popup** (**safe**: does **not** probe GUI-library versions)
- **Network Info popup** (host/IFs/routes/DNS)

---

## Requirements

- Python **3.8+**
- Preferred: `FreeSimpleGUI` (or `PySimpleGUI<5`)
- Required: `scapy`
- For HTTP helper: `fastapi`, `uvicorn`
- Optional: `tcpreplay` (for `sendpfast`)
- Admin/root privileges for raw sockets

---

## Installation

```bash
python -m venv .venv
# Windows
. .venv/Scripts/activate
# macOS/Linux
source .venv/bin/activate

pip install --upgrade pip
pip install FreeSimpleGUI scapy fastapi uvicorn
# Fallback if FreeSimpleGUI is unavailable
pip install "PySimpleGUI<5"
# PySimpleGUI v5 is not supported (the app targets v4 API).
```

## Run

> python scapy_gui.py
- Top bar: language, ports health (✅/❌), Env/Versions, Network Info buttons.
- A permission warning may appear on launch (raw sockets).

## Basic Usage

- Local Servers
  -  Start HTTP: launch FastAPI+Uvicorn (/healthz for reachability)
  -  Start UDP Echo: launch UDP echo server
> The Ports: indicator reflects HTTP/UDP status
- Receiver / Realtime
- BPF filter, rolling PCAP, CSV export
- DNS
- Select UDP/TCP/DoT; tweak EDNS/DO/NSID/EDE (subset)

## Missions

- Simple learning checkboxes (e.g., Ping succeeded)
- HTTP Helper API
- GET /healthz → {"status":"ok"}
- GET /echo?q=hello → "hello"
- GET /time → {"now": "YYYY-MM-DDTHH:MM:SSZ"}
- GET /static/* → served only when docroot is set

# Popups (Env/Versions & Network)

- Env/Versions
- Python/OS/OpenSSL, key module versions (Scapy/FastAPI/Uvicorn/…)
- sys.path, tcpreplay presence, conf.iface, helper server states
> Note: GUI library (FreeSimpleGUI/PySimpleGUI) versions are not probed to avoid vendor links/popups causing crashes.
- Network Info
- Hostname/FQDN, guessed local IPs
- Scapy IF list, bind candidates, route table, default route
- nameserver lines from /etc/resolv.conf (Unix-like)

## Troubleshooting

- GUI won’t start -> Ensure FreeSimpleGUI or PySimpleGUI<5 is installed
- Permission warning -> Re-run with Administrator/root/sudo
- HTTP helper shows ❌ -> Confirm fastapi/uvicorn installed, check port conflicts and local firewall
- DoT fails -> Verify outbound 853/TCP, and whether TLS interception exists

## Screenshots

See README.screenshots.md and place captures under ./screenshots/*.png.

## License

MIT License

## Credits

- GUI: FreeSimpleGUI / PySimpleGUI

- Networking: Scapy

- HTTP: FastAPI / Uvicorn

- Replay: tcpreplay


