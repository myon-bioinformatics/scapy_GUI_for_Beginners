# scapy_layer_tools_gui_v9_3.py — L2/L3 Toolkit (v9.3)
# - JP/EN UI toggle (top bar, legend, notes, missions title, status/buttons)
# - Active ports indicator (HTTP/UDP) on the top right
# - Interface dropdown + bind host dropdown (auto-populated)
# - Local servers under Endpoints (HTTP doc-root, UDP echo)
# - Realtime counters (sparkline + mini bar), rolling PCAP, CSV export
# - DNS over UDP/TCP/TLS (DoT) with EDNS/DO/NSID/EDE (subset)
# - Traceroute with parallel TTL + PTR lookup
# - PCAP sender with optional rewrite & sendpfast (tcpreplay if available)
# - Custom payload sender (ICMP/TCP/UDP/RAW)
# - FastAPI + Uvicorn HTTP helper with /healthz, /echo, /time (+ /static if docroot)
# - NEW: Env/Versions popup, Network Info popup
#
# Requirements:
#   pip install fastapi uvicorn "PySimpleGUI<5" scapy
#   (FreeSimpleGUI があればそちらを最優先で使用)

# =========================
#  Imports
# =========================
# --- standard ---
import sys, os, ssl, socket, json, time, threading, random, shutil, platform, importlib, textwrap
from datetime import datetime, timedelta
from pathlib import Path
from collections import Counter, deque
from typing import List, Optional, Dict

# --- Flexible SG import (v4優先) -------------------------
tp = os.path.join(os.path.dirname(__file__), "third_party")
if os.path.isdir(tp) and tp not in sys.path:
    sys.path.insert(0, tp)
_GUI_BACKEND = None

try:
    import FreeSimpleGUI as sg
    _GUI_BACKEND = "FreeSimpleGUI(v4 fork)"
except Exception:
    try:
        import PySimpleGUI as sg
        _GUI_BACKEND = "PySimpleGUI(v4 local/wrapper)"
    except Exception as e:
        raise ImportError(
            "No usable SG backend found. "
            "Place PySimpleGUI.py (v4) locally OR `pip install FreeSimpleGUI` "
        ) from e
finally:
    print(f"[INFO] GUI backend: {_GUI_BACKEND}")
# ---------------------------------------------------------

# --- FastAPI / Uvicorn (HTTP server) ---
try:
    from fastapi import FastAPI
    from fastapi.responses import PlainTextResponse, JSONResponse
    try:
        from fastapi.staticfiles import StaticFiles  # optional
        _HAS_STATIC = True
    except Exception:
        _HAS_STATIC = False
    _HAS_FASTAPI = True
except Exception:
    _HAS_FASTAPI = False
    _HAS_STATIC = False

try:
    import uvicorn
    _HAS_UVICORN = True
except Exception:
    _HAS_UVICORN = False

# --- third-party (Scapy) ---
from scapy import __version__ as _SCAPY_VER
from scapy.all import (
    IP, ICMP, TCP, UDP, Raw,
    Ether, ARP,
    sniff, wrpcap, PcapWriter,
    sr1, sr, srp, send, sendp,
    conf, getmacbyip, rdpcap, get_if_addr,
)
from scapy.layers.isakmp import ISAKMP, ISAKMP_payload_SA
from scapy.layers.dns import DNS, DNSQR, DNSRROPT

# =========================
#  Language (JP/EN)
# =========================
LANG = "JP"  # default

LP = {
    "JP": {
        "TITLE": "Scapy L2/L3 Toolkit (v9.3)",
        "ADMIN": "管理者権限",
        "YES": "はい",
        "NO": "いいえ",
        "LEGEND": "凡例:",
        "LEG_BEG": "🟢 初級",
        "LEG_INT": "🟡 中級",
        "LEG_ADV": "🔴 上級",
        "SRV_NOTE": "※ Endpoints=相手先IP、Local Servers=ローカルで立てる相手役",
        "MISSIONS": "📚 ミッション",
        "STATUS_READY": "準備完了。",
        "BTN_CANCEL": "中止",
        "BTN_EXIT": "終了",
        "LANG": "言語",
        "PORTS": "ポート:",
        "BTN_ENV": "Env/Versions",
        "BTN_NET": "Network Info",
    },
    "EN": {
        "TITLE": "Scapy L2/L3 Toolkit (v9.3)",
        "ADMIN": "Admin?",
        "YES": "Yes",
        "NO": "No",
        "LEGEND": "Legend:",
        "LEG_BEG": "🟢 Beginner",
        "LEG_INT": "🟡 Intermediate",
        "LEG_ADV": "🔴 Advanced",
        "SRV_NOTE": "Endpoints = remote peers, Local Servers = local helpers for labs.",
        "MISSIONS": "📚 Missions",
        "STATUS_READY": "Ready.",
        "BTN_CANCEL": "Cancel",
        "BTN_EXIT": "Exit",
        "LANG": "Lang",
        "PORTS": "Ports:",
        "BTN_ENV": "Env/Versions",
        "BTN_NET": "Network Info",
    }
}

# health flags
_http_ok = False
_udp_ok  = False

def _check_http_health(host: str, port: int, timeout: float = 1.0) -> bool:
    """GET /healthz に 200 が返るか確認"""
    try:
        target = "127.0.0.1" if host == "0.0.0.0" else host
        with socket.create_connection((target, port), timeout=timeout) as s:
            req = f"GET /healthz HTTP/1.0\r\nHost: {target}\r\n\r\n".encode()
            s.sendall(req)
            data = s.recv(1024) or b""
        return b" 200 " in data or data.startswith(b"HTTP/1.1 200")
    except Exception:
        return False

def _check_udp_echo_alive(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        target = "127.0.0.1" if host == "0.0.0.0" else host
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        payload = b"echo-health"
        s.sendto(payload, (target, port))
        data, _ = s.recvfrom(65535)
        s.close()
        return data == payload
    except Exception:
        return False

def L(key: str) -> str:
    return LP.get(LANG, LP["EN"]).get(key, key)

def apply_language():
    def _u(k, v):
        try:
            if k in window.AllKeysDict:
                window[k].update(v)
        except Exception:
            pass
    _u("-TITLE-", L("TITLE"))
    _u("-ADMIN_LABEL-", L("ADMIN"))
    _u("-ADMIN_VAL-", L("YES") if is_admin() else L("NO"))
    _u("-LANG_LABEL-", L("LANG"))
    _u("-PORTS_LABEL-", L("PORTS"))
    _u("-LEGEND-", L("LEGEND"))
    _u("-LEG_BEG-", L("LEG_BEG"))
    _u("-LEG_INT-", L("LEG_INT"))
    _u("-LEG_ADV-", L("LEG_ADV"))
    _u("-SRV_NOTE-", L("SRV_NOTE"))
    _u("-MISSIONS_TITLE-", L("MISSIONS"))
    _u("-STATUS-", L("STATUS_READY"))
    _u("-CANCEL-", L("BTN_CANCEL"))
    _u("-EXIT-", L("BTN_EXIT"))
    _u("-BTN_ENV-", L("BTN_ENV"))
    _u("-BTN_NET-", L("BTN_NET"))

# =========================
#  Helpers / Utilities
# =========================
def is_admin() -> bool:
    try:
        import ctypes
        if sys.platform.startswith("win"):
            return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[attr-defined]
        else:
            return (os.geteuid() == 0)  # type: ignore[attr-defined]
    except Exception:
        return False

def valid_ip(s: str) -> bool:
    try:
        parts = s.split(".")
        if len(parts) != 4: return False
        nums = [int(p) for p in parts]
        return all(0 <= n <= 255 for n in nums)
    except Exception:
        return False

def parse_port_range(s: str) -> List[int]:
    ports = set()
    s = (s or "").strip()
    if not s:
        return []
    for token in s.split(","):
        token = token.strip()
        if "-" in token:
            a,b = token.split("-",1)
            a, b = int(a), int(b)
            if a > b: a, b = b, a
            for p in range(a, b+1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            p = int(token)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)

def ttl_from(values) -> int:
    try: return min(255, max(1, int(values["-TTL-"])))
    except Exception: return 64

def timeout_from(values) -> int:
    try: return max(1, int(float(values["-TIMEOUT-"])))
    except Exception: return 5

def choose_sport() -> int:
    return random.randint(1024, 65535)

def choose_seq() -> int:
    return random.randint(0, 2**32-1)

def parse_payload(text: str, as_hex: bool) -> bytes:
    if not text: return b""
    if as_hex:
        cleaned = text.replace("0x", "").replace(" ", "").replace("\n", "")
        if len(cleaned) % 2 != 0: cleaned = "0" + cleaned
        return bytes.fromhex(cleaned)
    return text.encode("utf-8", errors="replace")

def has_sendpfast() -> bool:
    return shutil.which("tcpreplay") is not None

def nowstamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def make_sparkline(vals: List[int], width: int = 60) -> str:
    blocks = "▁▂▃▄▅▆▇"
    if not vals: return ""
    v = list(vals)[-width:]
    mx = max(v) or 1
    return "".join(blocks[min(6, int((x*6)/mx))] for x in v)

def ratio_bar(d: Dict[str,int], width: int = 40) -> str:
    total = sum(d.values()) or 1
    keys = ["TCP","UDP","ICMP","Other"]
    counts = [d.get("TCP",0), d.get("UDP",0), d.get("ICMP",0), d.get("Other",0)]
    bars = []
    for k,c in zip(keys,counts):
        n = int((c/total)*width)
        bars.append(k[0]*max(1,n))
    return " ".join(bars) + f"  (TCP:{counts[0]} UDP:{counts[1]} ICMP:{counts[2]} Other:{counts[3]})"

def bar_row(label: str, count: int, total: int, width: int = 40) -> str:
    total = total or 1
    n = int((count/total)*width)
    return f"{label:<5} | " + ("█"*n).ljust(width) + f" {count}"

# RFC 8914 subset mapping for EDE codes
EDE_MAP = {
    0: "Other Error / Unspecified",
    1: "Unsupported DNSKEY Algorithm",
    2: "Unsupported DS Digest Type",
    3: "Stale Answer",
    4: "Forged Answer",
    5: "DNSSEC Indeterminate",
    6: "DNSSEC Bogus",
    7: "Signature Expired",
    8: "Signature Not Yet Valid",
    9: "DNSKEY Missing",
    10: "RRSIGs Missing",
    11: "No Zone Key Bit Set",
    12: "NSEC Missing",
    13: "Cached Error",
    14: "Not Ready",
    15: "Blocked",
    16: "Censored",
    17: "Filtered",
    18: "Prohibited",
    19: "Stale NXDOMAIN Answer",
    20: "Not Authoritative",
    21: "Not Supported",
    22: "No Reachable Authority",
    23: "Network Error",
    24: "Invalid Data",
}

# =========================
#  Interface helpers
# =========================
def list_iface_names():
    try:
        return [str(v.name) for k,v in (conf.ifaces.data or {}).items() if getattr(v, "name", None)]
    except Exception:
        return [str(conf.iface)] if conf.iface else []

def iface_ip_map():
    m = {}
    try:
        for k,v in (conf.ifaces.data or {}).items():
            name = str(v.name) if getattr(v, "name", None) else None
            if not name: continue
            try:
                ip = get_if_addr(name)
                if ip and ip != "0.0.0.0":
                    m[name] = ip
            except Exception:
                continue
    except Exception:
        pass
    return m

def bind_candidates(extra=None):
    c = ["0.0.0.0", "127.0.0.1"]
    m = iface_ip_map()
    for ip in m.values():
        if ip not in c:
            c.append(ip)
    if extra:
        for x in extra:
            if x and x not in c:
                c.append(x)
    return c

# =========================
#  GUI
# =========================
sg.theme("Reddit")

legend = [
    sg.Text("Legend:", key="-LEGEND-"),
    sg.Text("🟢 Beginner", text_color="green", key="-LEG_BEG-"),
    sg.Text("🟡 Intermediate", text_color="goldenrod", key="-LEG_INT-"),
    sg.Text("🔴 Advanced", text_color="firebrick", key="-LEG_ADV-"),
]

# NEW: utility buttons row (Env/Versions & Net info)
utility_row = [
    sg.Button("Env/Versions", key="-BTN_ENV-", tooltip="Show environment & versions"),
    sg.Button("Network Info", key="-BTN_NET-", tooltip="Show interfaces/routes etc."),
]

iface_frame = [
    [sg.Text("🟡 Interface"),
     sg.Combo(values=list_iface_names(), key="-IFACE_PICK-", size=(30,1), readonly=True, enable_events=True),
     sg.Button("Refresh", key="-IFACE_REFRESH-"),
     sg.Text("or"), sg.Input("", key="-IFACE-", size=(20,1)), sg.Button("Use", key="-USE_IFACE-"),
     sg.Text("Current:"), sg.Text(conf.iface or "", key="-CUR_IFACE-", size=(25,1))]
]

servers_frame = [
    [sg.Text("🟢 Local Servers (lab)"),
     sg.Text("※ Endpoints はパケットの送信先/送信元IP。Local Servers は教材用にローカルで立てるサーバです。", key="-SRV_NOTE-")],
    [sg.Text("Bind host"), sg.Combo(values=bind_candidates(), default_value="0.0.0.0", key="-SRV_BIND-", size=(14,1), readonly=True), sg.Button("Refresh binds", key="-SRV_BIND_REFRESH-"),
     sg.Text("HTTP port"), sg.Input("8000", key="-HTTP_PORT-", size=(6,1)),
     sg.Text("Doc root"), sg.Input(key="-HTTP_ROOT-", size=(38,1)), sg.FolderBrowse("Browse"),
     sg.Button("Start HTTP", key="-HTTP_START-"), sg.Button("Stop HTTP", key="-HTTP_STOP-")],
    [sg.Text("UDP Echo port"), sg.Input("9999", key="-UDP_PORT-", size=(6,1)),
     sg.Button("Start UDP Echo", key="-UDP_START-"), sg.Button("Stop UDP", key="-UDP_STOP-")],
]

dns_frame = [
    [sg.Text("🟢/🟡 DNS Query Sender (UDP/TCP/DoT + EDNS/DO/NSID/EDE)", key="-DNS_TITLE-")],
    [sg.Text("Resolver IP"), sg.Input("8.8.8.8", key="-DNS_DST-", size=(16,1)),
     sg.Text("Qname"), sg.Input("example.com", key="-DNS_QNAME-", size=(25,1)),
     sg.Text("Qtype"), sg.Combo(["A","AAAA","TXT","MX","NS","CNAME"], default_value="A", key="-DNS_QTYPE-", readonly=True, size=(6,1)),
     sg.Text("Transport"), sg.Combo(["UDP","TCP","DoT"], default_value="UDP", key="-DNS_TRAN-", readonly=True, size=(6,1))],
    [sg.Checkbox("Use EDNS0 (OPT RR)", key="-DNS_EDNS-", default=True),
     sg.Checkbox("Set DO (DNSSEC OK)", key="-DNS_DO-", default=False),
     sg.Text("UDP Payload Size"), sg.Input("1232", key="-DNS_BUFSZ-", size=(6,1)),
     sg.Text("NSID"), sg.Input("", key="-DNS_NSID-", size=(10,1)),
     sg.Text("EDE code"), sg.Input("", key="-DNS_EDE_CODE-", size=(6,1)),
     sg.Text("EDE text"), sg.Input("", key="-DNS_EDE_TEXT-", size=(16,1))],
    [sg.Text("Count"), sg.Input("1", key="-DNS_COUNT-", size=(6,1)),
     sg.Text("Interval(s)"), sg.Input("0.2", key="-DNS_INTERVAL-", size=(7,1)),
     sg.Button("Send DNS", key="-DNS_SEND-"),
     sg.Button("EDE Help", key="-DNS_EDE_HELP-")]
]

arp_frame = [
    [sg.Text("🟡 ARP Scan", key="-ARP_TITLE-")],
    [sg.Text("Target (CIDR/range)", key="-ARP_TGT_LABEL-"), sg.Input("192.168.1.0/24", key="-ARP_TARGET-", size=(22,1)),
     sg.Text("Timeout(s)"), sg.Input("2", key="-ARP_TIMEOUT-", size=(6,1)),
     sg.Button("Start ARP Scan", key="-ARP_SCAN-")]
]

trace_frame = [
    [sg.Text("🟢/🟡/🔴 Traceroute (parallel + PTR)", key="-TR_TITLE-")],
    [sg.Text("Mode", key="-MODE_LABEL-"), sg.Combo(["ICMP","UDP","TCP"], default_value="ICMP", key="-TR_MODE-", readonly=True, size=(6,1)),
     sg.Text("Max Hops", key="-MAX_LABEL-"), sg.Input("20", key="-TR_MAX-", size=(6,1)),
     sg.Text("Per-hop Timeout(s)", key="-PERHOP_LABEL-"), sg.Input("2", key="-TR_TIMEOUT-", size=(6,1)),
     sg.Text("Probes/TTL", key="-PROBES_LABEL-"), sg.Input("3", key="-TR_PROBES-", size=(4,1)),
     sg.Text("Parallel TTL", key="-PARALLEL_LABEL-"), sg.Checkbox("On", key="-TR_PARALLEL-", default=False),
     sg.Text("dport (UDP/TCP)", key="-DPORT2_LABEL-"), sg.Input("33434", key="-TR_DPORT-", size=(7,1)),
     sg.Checkbox("PTR lookup", key="-TR_PTR-", default=True),
     sg.Button("Start Traceroute", key="-TR_START-")]
]

pcap_frame = [
    [sg.Text("🟡/🔴 PCAP Sender")],
    [sg.Text("File (.pcap / .pcapng)"),
     sg.Input(key="-PCAP_FILE-", size=(45,1)), sg.FileBrowse(file_types=(("pcap/pcapng","*.pcap;*.pcapng"),)),
     sg.Checkbox("Rewrite IP(src/dst)", default=True, key="-REWRITEIP-"),
     sg.Checkbox("Send L2 (sendp)", default=True, key="-SENDL2-"),
     sg.Checkbox("Send L3 (send)", default=True, key="-SENDL3-")],
    [sg.Text("Repeat Count"), sg.Input("1", key="-PCAP_COUNT-", size=(6,1)),
     sg.Text("Interval(s)"), sg.Input("0.05", key="-PCAP_INTERVAL-", size=(7,1)),
     sg.Text("sendpfast (tcpreplay)"), sg.Checkbox("Use if available", key="-FAST-", default=False),
     sg.Text("pps"), sg.Input("0", key="-FAST_PPS-", size=(6,1)), sg.Text("(0 = as fast as possible)")],
    [sg.Button("Send PCAP", key="-PCAP-")]
]

sniffer_frame = [
    [sg.Text("🟡 Receiver / Realtime", key="-RECV_TITLE-")],
    [sg.Text("BPF filter", key="-BPF_LABEL-"), sg.Input("tcp or icmp or port 53", key="-SNIF_FILTER-", size=(28,1)),
     sg.Text("Timeout(s)"), sg.Input("0", key="-SNIF_TIMEOUT-", size=(6,1)),
     sg.Checkbox("Rolling PCAP", key="-SNIF_ROLL-", default=False),
     sg.Text("Every(sec)", key="-EVERY_LABEL-"), sg.Input("60", key="-SNIF_ROLL_SEC-", size=(5,1)),
     sg.Text("or Size(MB)", key="-ORSIZE_LABEL-"), sg.Input("5", key="-SNIF_ROLL_MB-", size=(5,1)),
     sg.Button("Start Live Sniff", key="-SNIFF_LIVE-"),
     sg.Button("Stop", key="-SNIFF_STOP-")],
    [sg.Text("PPS (last 60s)", key="-PPS_LABEL-"), sg.Text("", key="-SPARK-", size=(64,1))],
    [sg.Text("Protocol ratio", key="-RATIO_LABEL-"), sg.Text("", key="-RATIO-", size=(64,1))],
    [sg.Multiline(key="-MINIBAR-", size=(64,5), disabled=True, autoscroll=False)],
    [sg.Text("Save last snapshot", key="-SAVE_SNAP_LABEL-"), sg.Input(f"sniff_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap", key="-SNIF_OUT-", size=(35,1)),
     sg.Button("Save Snapshot", key="-SNIFF_SAVE-"),
     sg.Text("Export CSV", key="-CSV_LABEL-"), sg.Input(f"metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", key="-CSV_OUT-", size=(30,1)),
     sg.Button("Export", key="-CSV_EXPORT-")]
]

payload_frame = [
    [sg.Text("🔴 Training / Custom Payload Sender", key="-PAY_TITLE-")],
    [sg.Text("Protocol", key="-PROTO_LABEL-"), sg.Combo(["ICMP","TCP","UDP","RAW"], default_value="UDP", key="-CP_PROTO-", readonly=True, size=(8,1)),
     sg.Text("sport", key="-SPORT_LABEL-"), sg.Input("", key="-CP_SPORT-", size=(7,1)),
     sg.Text("dport", key="-DPORT3_LABEL-"), sg.Input("12345", key="-CP_DPORT-", size=(7,1)),
     sg.Text("Count", key="-COUNT2_LABEL-"), sg.Input("1", key="-CP_COUNT-", size=(6,1)),
     sg.Text("Interval(s)", key="-INTERVAL2_LABEL-"), sg.Input("0.2", key="-CP_INTERVAL-", size=(7,1)),
     sg.Checkbox("sendp(L2)", key="-CP_L2-", default=False),
     sg.Button("Sample Payload", key="-CP_SAMPLE-")],
    [sg.Text("Payload", key="-PAYBODY_LABEL-")],
    [sg.Multiline(size=(92,5), key="-CP_DATA-"),
     sg.Column([[sg.Checkbox("Interpret as HEX", key="-CP_HEX-", default=False)],
                [sg.Button("Send Payload", key="-CP_SEND-")]])],
]

missions_frame = [
    [sg.Text("📚 Missions", key="-MISSIONS_TITLE-"), sg.Text("Hints language", key="-HINTS_LANG_LABEL-"),
     sg.Combo(["EN","JP"], default_value="JP", key="-HINT_LANG-", readonly=True, size=(4,1)),
     sg.Button("Show Hints", key="-MS_HINTS-"),
     sg.Button("Sample DNS", key="-MS_DNS_SAMPLE-")],
    [sg.Checkbox("🟢 Ping 2-way 成功", key="-MS_PING-", default=False, disabled=True),
     sg.Checkbox("🟢 DNS A 取得", key="-MS_DNS-", default=False, disabled=True)],
    [sg.Checkbox("🟡 SYN 3-way 成功", key="-MS_SYN3-", default=False, disabled=True),
     sg.Checkbox("🟡 ARP Scan 実施", key="-MS_ARP-", default=False, disabled=True)],
    [sg.Checkbox("🔴 Traceroute(TCP) 到達", key="-MS_TRTCP-", default=False, disabled=True),
     sg.Checkbox("🔴 Custom Payload 送信", key="-MS_PAY-", default=False, disabled=True)],
]

level1_row = [
    sg.Text("🟢 基本 (Level 1)", key="-L1_HDR-"),
    sg.Button("🟢 Ping 1-way", key="-PING1-"),
    sg.Button("🟢 Ping 2-way", key="-PING2-"),
    sg.Button("🟡 SYN 1-way", key="-SYN1-"),
    sg.Button("🟡 SYN 3-way", key="-SYN3-"),
]

level2_row = [
    sg.Text("🟡 応用 (Level 2)", key="-L2_HDR-"),
    sg.Button("🟡 TCP Scan", key="-TCPSCAN-"),
    sg.Button("🟢 Routes", key="-ROUTES-"),
    sg.Button("🟢 Get MAC", key="-GETMAC-"),
]

adv_row = [
    sg.Text("🔴 上級 (Advanced)", key="-ADV_HDR-"),
    sg.Button("🔴 Xmas Scan", key="-XMAS-"),
    sg.Button("🔴 IKE Probe", key="-IKE-"),
]

content_layout = [
    [sg.Text(L("TITLE"), key="-TITLE-"), sg.Push(),
     sg.Text(L("PORTS"), key="-PORTS_LABEL-"), sg.Text("-", key="-PORTS-", size=(28,1)),
     sg.Text(L("LANG"), key="-LANG_LABEL-"), sg.Combo(["JP","EN"], default_value="JP", key="-LANG-", readonly=True, enable_events=True, size=(4,1)),
     sg.Text(L("ADMIN"), key="-ADMIN_LABEL-"), sg.Text("Yes" if is_admin() else "No", text_color=("green" if is_admin() else "red"), key="-ADMIN_VAL-")],
    utility_row,
    legend,
    [sg.Frame("🟡 Interface", iface_frame)],
    [sg.Frame("🟢 Endpoints", [
        [sg.Text("Source IPv4"), sg.Input("", key="-SRC-", size=(20,1)),
         sg.Text("Destination IPv4"), sg.Input("127.0.0.1", key="-DST-", size=(20,1))],
        [sg.Text("TTL"), sg.Input("64", key="-TTL-", size=(6,1)),
         sg.Text("Timeout(s)"), sg.Input("5", key="-TIMEOUT-", size=(6,1)),
         sg.Text("Retries"), sg.Input("0", key="-RETRIES-", size=(6,1))],
        ])],
    [sg.Frame("🟢 Local Servers", servers_frame)],
    [sg.Frame("🟡 Port Options", [
        [sg.Text("TCP dport (SYN1/3)"), sg.Input("80", key="-DPORT-", size=(8,1)),
         sg.Text("TCP Xmas dport"), sg.Input("666", key="-XPORT-", size=(8,1)),
         sg.Text("TCP Scan ports"), sg.Input("1-1024", key="-SCANRANGE-", size=(18,1))]
    ])],
    [sg.Frame("🟡/🔴 PCAP Sender", pcap_frame)],
    level1_row,
    level2_row,
    adv_row,
    [sg.Frame("🟢/🟡 DNS", dns_frame)],
    [sg.Frame("🟡 ARP", arp_frame)],
    [sg.Frame("🟢/🟡/🔴 Traceroute", trace_frame)],
    [sg.Frame("🔴 Payload", payload_frame)],
    [sg.Frame("🟡 Receiver (Realtime)", sniffer_frame)],
    [sg.Frame("📚 Missions", missions_frame)],
    [sg.ProgressBar(max_value=100, orientation="h", size=(70,20), key="-PROG-")],
    [sg.Multiline(key="-LOG-", size=(120,22), autoscroll=True, expand_x=True, reroute_stdout=False, reroute_stderr=False)],
    [sg.StatusBar("", size=(100,1), key="-STATUS-"),
     sg.Push(), sg.Button(L("BTN_CANCEL"), key="-CANCEL-", button_color=("white","firebrick3")), sg.Button(L("BTN_EXIT"), key="-EXIT-")]
]

layout = [[sg.Column(content_layout, scrollable=True, vertical_scroll_only=True, size=(1100, 760), key='-SCROLL-')]]

window = sg.Window("scapy_layer_tools_gui_v9_3.py", layout, resizable=True, finalize=True)
stop_flag = threading.Event()
_last_sniff = []  # snapshot
_live_writer = None  # type: Optional[PcapWriter]
_live_rotate_next = None  # type: Optional[datetime]
_live_roll_sec = 0
_live_roll_mb = 0
_live_base = Path(f"live_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
pps_hist = deque(maxlen=60)  # last 60 sec
proto_counts = Counter()
last_sec_count = 0
sniff_running = False
pcap_index = []  # rolling index entries

# Simple servers (HTTP via FastAPI/Uvicorn, UDP echo via socket)
_http_thread: Optional[threading.Thread] = None
_http_server: Optional["uvicorn.Server"] = None
_http_stop = threading.Event()
_udp_thread: Optional[threading.Thread] = None
_udp_stop = threading.Event()
_udp_sock: Optional[socket.socket] = None

# Track active server ports/binds
_http_port: Optional[int] = None
_http_bind: Optional[str] = None
_udp_port: Optional[int] = None
_udp_bind: Optional[str] = None

def update_ports_label():
    parts = []
    if _http_port:
        mark = "✅" if _http_ok else "❌"
        parts.append(f"{mark} HTTP:{_http_port}@{_http_bind or '0.0.0.0'}")
    if _udp_port:
        mark = "✅" if _udp_ok else "❌"
        parts.append(f"{mark} UDP:{_udp_port}@{_udp_bind or '0.0.0.0'}")
    txt = " | ".join(parts) if parts else "-"
    try:
        window["-PORTS-"].update(txt)
    except Exception:
        pass

def set_status(msg: str) -> None:
    try: window["-STATUS-"].update(msg)
    except Exception: pass

def log(msg: str) -> None:
    try: window["-LOG-"].print(msg)
    except Exception: pass

# =========================
#  Env/Versions & Network popups (NEW)
# =========================
def _ver_of(mod: str) -> str:
    try:
        m = importlib.import_module(mod)
        v = getattr(m, "__version__", None)
        if v is None and hasattr(m, "version"):
            v = getattr(m, "version")
        return str(v or "unknown")
    except Exception:
        return "not installed"

def show_env_versions_popup():
    # Core environment
    lines = []
    lines.append("# Environment / Versions")
    lines.append(f"Time: {datetime.now().isoformat(sep=' ', timespec='seconds')}")
    lines.append(f"Admin: {'Yes' if is_admin() else 'No'}")
    lines.append("")
    lines.append("## Python")
    lines.append(f"Python: {sys.version.split()[0]}  ({sys.version.splitlines()[0]})")
    lines.append(f"Executable: {sys.executable}")
    lines.append(f"Platform: {platform.platform()}")
    lines.append(f"Machine: {platform.machine()} / Processor: {platform.processor() or 'N/A'}")
    lines.append(f"OpenSSL: {ssl.OPENSSL_VERSION}")
    lines.append("")
    lines.append("## GUI Backend (no version probing)")
    # IMPORTANT: avoid importing PySimpleGUI/FreeSimpleGUI here — some distributions may crash or prompt
    lines.append(f"Backend: {_GUI_BACKEND}")
    lines.append("")
    lines.append("## Paths")
    lines.append(f"Working dir: {os.getcwd()}")
    lines.append("PYTHONPATH / sys.path:")
    for p in sys.path[:15]:
        lines.append(f"  - {p}")
    if len(sys.path) > 15:
        lines.append("  ...")
    lines.append("")
    lines.append("## Modules (selected)")
    # Do NOT import GUI libs again here. Keep them commented out.
    # lines.append(f"FreeSimpleGUI: {_ver_of('FreeSimpleGUI')}")  # removed
    # lines.append(f"PySimpleGUI:   <skipped>")                   # removed
    lines.append(f"Scapy:       {_SCAPY_VER}")
    lines.append(f"FastAPI:     {_ver_of('fastapi')}")
    lines.append(f"Uvicorn:     {_ver_of('uvicorn')}")
    lines.append(f"Requests:    {_ver_of('requests')}")
    lines.append(f"dpkt:        {_ver_of('dpkt')}")
    lines.append(f"pcapy:       {_ver_of('pcapy')}")
    lines.append(f"pyshark:     {_ver_of('pyshark')}")
    lines.append("")
    lines.append("## Capabilities / Tools")
    lines.append(f"tcpreplay (sendpfast): {'yes' if has_sendpfast() else 'no'}")
    try:
        libpcap_used = getattr(conf, 'use_pcap', None)
        lines.append(f"scapy conf.use_pcap: {libpcap_used if libpcap_used is not None else 'N/A'}")
    except Exception:
        lines.append("scapy conf.use_pcap: N/A")
    lines.append(f"Default iface (conf.iface): {conf.iface or '(not set)'}")
    if _http_port:
        lines.append(f"HTTP helper: {_http_bind}:{_http_port} ({'OK' if _http_ok else 'NG'})")
    if _udp_port:
        lines.append(f"UDP echo:    {_udp_bind}:{_udp_port} ({'OK' if _udp_ok else 'NG'})")
    text = "\n".join(lines)
    sg.popup_scrolled(text, title="Environment & Versions", size=(100, 30), non_blocking=False)

def _default_route_from_scapy():
    try:
        # Find default route (0.0.0.0)
        if hasattr(conf.route, "routes"):
            for dst, gw, iface, flags, metric in getattr(conf.route, "routes", []):
                if str(dst) == "0.0.0.0":
                    return f"gw={gw} iface={iface} metric={metric} flags={flags}"
    except Exception:
        pass
    return "N/A"

def _local_ips_guess():
    ips = set()
    try:
        hn = socket.gethostname()
        ips.add(socket.gethostbyname(hn))
        for fam in (socket.AF_INET,):
            try:
                for info in socket.getaddrinfo(hn, None, fam, socket.SOCK_STREAM):
                    ip = info[4][0]
                    if ip and ip != "127.0.0.1":
                        ips.add(ip)
            except Exception:
                pass
    except Exception:
        pass
    return sorted(ips)

def show_network_info_popup():
    lines = []
    lines.append("# Network Information")
    lines.append(f"Time: {datetime.now().isoformat(sep=' ', timespec='seconds')}")
    lines.append("")
    lines.append("## Host")
    try:
        lines.append(f"Hostname: {socket.gethostname()}")
        fqdn = socket.getfqdn()
        lines.append(f"FQDN:     {fqdn}")
    except Exception:
        lines.append("Hostname/FQDN: N/A")
    ips = _local_ips_guess()
    lines.append(f"Local IPs (guess): {', '.join(ips) if ips else 'N/A'}")
    lines.append("")
    lines.append("## Interfaces (Scapy)")
    try:
        ifaces = conf.ifaces.data or {}
        for k, v in ifaces.items():
            nm = getattr(v, "name", k)
            lines.append(f"- {k}: {nm} ({get_if_addr(nm) if nm else 'N/A'})")
    except Exception as e:
        lines.append(f"(error enumerating ifaces: {e})")
    lines.append("")
    lines.append("## Bind candidates (for servers)")
    try:
        for ip in bind_candidates():
            lines.append(f"- {ip}")
    except Exception:
        lines.append("- N/A")
    lines.append("")
    lines.append("## Route table (Scapy conf.route)")
    try:
        lines.append(str(conf.route))
    except Exception as e:
        lines.append(f"(error: {e})")
    lines.append("")
    lines.append(f"Default route (parsed): {_default_route_from_scapy()}")
    lines.append("")
    lines.append("## DNS resolvers")
    resolvers = []
    if os.name != "nt":
        try:
            p = Path("/etc/resolv.conf")
            if p.exists():
                for ln in p.read_text().splitlines():
                    ln = ln.strip()
                    if ln.startswith("nameserver"):
                        parts = ln.split()
                        if len(parts) >= 2:
                            resolvers.append(parts[1])
        except Exception:
            pass
    else:
        lines.append("(Windows: use ipconfig /all for full detail)")
    if resolvers:
        lines.append("nameserver(s): " + ", ".join(resolvers))
    text = "\n".join(lines)
    sg.popup_scrolled(text, title="Network Info", size=(100, 30), non_blocking=False)

# =========================
#  Core Workers
# =========================
def ping_one_way(src: str, dst: str, ttl: int) -> None:
    send(IP(src=src, dst=dst, ttl=ttl)/ICMP(), verbose=False)
    log("[info] Sent ICMP Echo Request (no wait).")

def ping_two_way(src: str, dst: str, ttl: int, timeout: int, retries: int) -> None:
    req = IP(src=src, dst=dst, ttl=ttl)/ICMP()
    ans = None
    for i in range(max(1, retries + 1)):
        if stop_flag.is_set(): return
        log(f"[try {i+1}] Sending ICMP Echo...")
        ans = sr1(req, timeout=timeout, verbose=False)
        if ans: break
    if ans:
        log("=== ICMP Echo Reply ==="); log(ans.summary())
        window["-MS_PING-"].update(True)
        try: log(ans.show(dump=True))
        except Exception: pass
    else:
        log("[warn] No ICMP reply (timeout).")

def syn_one_way(src: str, dst: str, ttl: int, dport: int) -> None:
    sport, seq = choose_sport(), choose_seq()
    send(IP(src=src, dst=dst, ttl=ttl)/TCP(sport=sport, dport=dport, flags="S", seq=seq), verbose=False)
    log(f"[info] Sent SYN to {dst}:{dport} (no wait).")

def syn_three_way(src: str, dst: str, ttl: int, dport: int, timeout: int, retries: int) -> None:
    ip = IP(src=src, dst=dst, ttl=ttl)
    sport, seq = choose_sport(), choose_seq()
    syn = ip/TCP(sport=sport, dport=dport, flags="S", seq=seq)
    synack = None
    for i in range(max(1, retries + 1)):
        if stop_flag.is_set(): return
        log(f"[try {i+1}] SYN → wait for SYN/ACK...")
        synack = sr1(syn, timeout=timeout, verbose=False)
        if synack: break
    if not synack:
        log("[warn] No SYN/ACK (closed/filtered or timeout)."); return
    log("=== SYN/ACK received ==="); log(synack.summary())
    window["-MS_SYN3-"].update(True)
    try: log(synack.show(dump=True))
    except Exception: pass
    ack_pkt = ip/TCP(sport=sport, dport=dport, flags="A", seq=synack.ack, ack=synack.seq + 1)
    send(ack_pkt, verbose=False)
    log("[info] Sent final ACK. (3-way handshake complete)")

def tcp_scan(src: str, dst: str, ttl: int, timeout: int, retries: int, ports: List[int]) -> None:
    if not ports: log("[error] No ports specified for scan."); return
    sport = choose_sport()
    answered, unanswered = sr(IP(src=src, dst=dst, ttl=ttl)/TCP(flags="S", sport=sport, dport=ports),
                              timeout=timeout, retry=retries, verbose=False)
    open_ports, closed_filtered = [], []
    for s, r in (answered or []):
        if r.haslayer(TCP):
            if "SA" in r.sprintf("%TCP.flags%"): open_ports.append(r.sport)
            elif "RA" in r.sprintf("%TCP.flags%") or "R" in r.sprintf("%TCP.flags%"):
                closed_filtered.append((r.sport, "closed"))
            else:
                closed_filtered.append((r.sport, f"flags={r.getlayer(TCP).flags}"))
    if unanswered:
        for p in ports:
            if p not in open_ports and all(p != pair[0] for pair in closed_filtered):
                closed_filtered.append((p, "filtered? (no answer)"))
    if open_ports:
        log("=== OPEN PORTS ==="); [log(f"{p}/tcp open") for p in sorted(set(open_ports))]
    else:
        log("[info] No open ports detected (or blocked).")
    if closed_filtered:
        log("=== OTHERS ==="); [log(f"{p}/tcp {st}") for p, st in sorted(set(closed_filtered))]

def show_routes() -> None:
    try:
        log("=== IPv4 Route Table ==="); log(str(conf.route))
        if hasattr(conf.route, "routes"):
            log("--- raw tuples (dst, gw, iface, flags, metric) ---")
            for row in conf.route.routes: log(str(row))
    except Exception as e:
        log(f"[error] route display failed: {e}")

def get_macs(src: str, dst: str) -> None:
    log("=== MAC by IP (ARP) ===")
    log(f"Source {src} -> {getmacbyip(src) or 'N/A'}")
    log(f"Dest   {dst} -> {getmacbyip(dst) or 'N/A'}")

def xmas_scan(src: str, dst: str, ttl: int, dport: int, timeout: int) -> None:
    sport = choose_sport()
    pkt = IP(src=src, dst=dst, ttl=ttl)/TCP(sport=sport, dport=dport, flags="FPU")
    log(f"[info] Xmas to {dst}:{dport}...")
    ans = sr1(pkt, timeout=timeout, verbose=False)
    if ans:
        log("=== Xmas response ==="); log(ans.summary())
        try: log(ans.show(dump=True))
        except Exception: pass
    else:
        log("[info] No response (open|filtered per RFC behavior).")

def ike_probe(src: str, dst: str, ttl: int, timeout: int, retries: int) -> None:
    base = IP(src=src, dst=dst, ttl=ttl)/UDP(sport=choose_sport(), dport=500)
    proposals = base/ISAKMP()/ISAKMP_payload_SA()
    log(f"[info] IKEv1 probe to {dst}:500...")
    answered, _ = sr(proposals, timeout=timeout, retry=retries, verbose=False)
    count = 0
    for s, r in (answered or []):
        if r.haslayer(ISAKMP):
            count += 1; log(f"[{count}] From {r.src} ISAKMP detected")
            try: log(r.show(dump=True))
            except Exception: pass
    if count == 0: log("[info] No ISAKMP response")

def send_pcap(src: str, dst: str, pcap_path: Path, rewrite_ip: bool, do_l2: bool, do_l3: bool,
              count: int, interval: float, use_fast: bool, pps: int) -> None:
    if not pcap_path.exists(): log("[error] PCAP not found."); return
    pkts = rdpcap(str(pcap_path))
    log(f"[info] Loaded {len(pkts)} packets from {pcap_path.name}")
    if rewrite_ip:
        changed = 0
        for p in pkts:
            if IP in p:
                p[IP].src = src or p[IP].src
                p[IP].dst = dst or p[IP].dst
                if hasattr(p[IP], "chksum"): del p[IP].chksum
                changed += 1
        log(f"[info] Rewrote IPs for {changed} packets")
    count = max(1, int(count)); interval = max(0.0, float(interval))
    if use_fast and has_sendpfast() and do_l2:
        tmp = Path(f"__tmp_replay_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"); wrpcap(str(tmp), pkts)
        try:
            log(f"[info] sendpfast: {count} loop(s), pps={pps if pps>0 else 'max'}")
            from scapy.sendrecv import sendpfast as _spf
            for i in range(count):
                if stop_flag.is_set(): break
                _spf(tmp, pps=pps if pps>0 else None, iface=conf.iface)
                log(f"[info] sendpfast burst {i+1}/{count}")
                if i < count - 1 and interval > 0: time.sleep(interval)
        finally:
            try: tmp.unlink()
            except Exception: pass
    else:
        for i in range(count):
            if stop_flag.is_set(): break
            if do_l3: send(pkts, verbose=False)
            if do_l2: sendp(pkts, verbose=False)
            log(f"[info] Sent PCAP burst {i+1}/{count}")
            if i < count - 1 and interval > 0: time.sleep(interval)
    log("[info] PCAP sending complete.")

def send_custom_payload(src: str, dst: str, ttl: int, proto: str,
                        sport_s: str, dport_s: str,
                        payload_text: str, as_hex: bool,
                        count_s: str, interval_s: str, send_l2: bool) -> None:
    if not valid_ip(src) or not valid_ip(dst): log("[error] Invalid source or destination IP."); return
    ttl = max(1, min(255, int(ttl)))
    try: count = max(1, int((count_s or "1").strip()))
    except Exception: count = 1
    try: interval = max(0.0, float((interval_s or "0").strip()))
    except Exception: interval = 0.0
    try: sport = int(sport_s) if (sport_s or "").strip() else choose_sport()
    except Exception: sport = choose_sport()
    try: dport = int(dport_s) if (dport_s or "").strip() else 0
    except Exception: dport = 0
    data = parse_payload(payload_text, as_hex)
    base = IP(src=src, dst=dst, ttl=ttl)
    for i in range(count):
        if stop_flag.is_set(): break
        if proto == "ICMP":
            pkt = base/ICMP()/Raw(load=data)
        elif proto == "TCP":
            if dport <= 0: dport = 12345
            pkt = base/TCP(sport=sport, dport=dport, flags="PA", seq=choose_seq())/Raw(load=data)
        elif proto == "UDP":
            if dport <= 0: dport = 12345
            pkt = base/UDP(sport=sport, dport=dport)/Raw(load=data)
        else:  # RAW
            pkt = base/Raw(load=data)
        (sendp if send_l2 else send)(pkt, verbose=False)
        window["-MS_PAY-"].update(True)
        log(f"[info] Sent {proto} payload {i+1}/{count} ({len(data)} bytes)")
        if i < count - 1 and interval > 0: time.sleep(interval)
    log("[info] Custom payload sending complete.")

def list_ifaces() -> None:
    try:
        ifaces = conf.ifaces.data
        log("=== Interfaces ===")
        for k, v in ifaces.items(): log(f"{k}: {v}")
    except Exception as e:
        log(f"[error] iface list failed: {e}")

def set_iface(name: str) -> None:
    try:
        if not name.strip():
            log("[warn] iface name is empty."); return
        conf.iface = name.strip()
        log(f"[info] Set conf.iface = {conf.iface}")
        try:
            window["-CUR_IFACE-"].update(conf.iface)
            window["-SRV_BIND-"].update(values=bind_candidates(), value="0.0.0.0")
        except Exception:
            pass
    except Exception as e:
        log(f"[error] set iface failed: {e}")

# =========================
#  DNS senders (UDP/TCP/DoT)
# =========================
def build_dns_packet(src: str, dst_dns: str, ttl: int, qname: str, qtype: str,
                     use_edns: bool, do_bit: bool, bufsize_s: str,
                     nsid: str, ede_code_s: str, ede_text: str):
    try: bufsize = max(512, int(bufsize_s or "1232"))
    except Exception: bufsize = 1232
    dns = DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    if use_edns or do_bit or nsid or ede_code_s:
        z = 0x8000 if do_bit else 0
        opts = []
        if nsid is not None and nsid != "":
            try: opts.append(("NSID", nsid.encode("ascii", "ignore")))
            except Exception: pass
        if ede_code_s:
            try:
                code = int(ede_code_s)
                desc = EDE_MAP.get(code, "Unknown EDE code")
                log(f"[EDE] {code}: {desc}")
                opts.append(("EDE", (code, ede_text or desc)))
            except Exception:
                pass
        try:
            opt = DNSRROPT(rclass=bufsize, z=z, options=opts or None)
            dns = dns/opt
        except Exception:
            try:
                opt = DNSRROPT(rclass=bufsize, z=z)
                dns = dns/opt
            except Exception:
                pass
    return IP(src=src, dst=dst_dns, ttl=ttl), dns

def dns_send_udp(src: str, dst_dns: str, ttl: int, qname: str, qtype: str, count: int, interval: float, timeout: int,
                 use_edns: bool, do_bit: bool, bufsize_s: str, nsid: str, ede_code_s: str, ede_text: str) -> None:
    if not (valid_ip(src) and valid_ip(dst_dns)): log("[error] Invalid IP."); return
    for i in range(max(1,count)):
        if stop_flag.is_set(): break
        ip, dns = build_dns_packet(src, dst_dns, ttl, qname, qtype, use_edns, do_bit, bufsize_s, nsid, ede_code_s, ede_text)
        pkt = ip/UDP(sport=choose_sport(), dport=53)/dns
        ans = sr1(pkt, timeout=timeout, verbose=False)
        if ans and ans.haslayer(DNS):
            log(f"[{i+1}] DNS/UDP response:"); window["-MS_DNS-"].update(True)
            try: log(ans.show(dump=True))
            except Exception: pass
        else:
            log(f"[{i+1}] No DNS response.")
        if i < count - 1 and interval > 0: time.sleep(interval)
    log("[info] DNS/UDP sending complete.")

def dns_send_tcp(src: str, dst_dns: str, ttl: int, qname: str, qtype: str, count: int, interval: float, timeout: int,
                 use_edns: bool, do_bit: bool, bufsize_s: str, nsid: str, ede_code_s: str, ede_text: str) -> None:
    if not (valid_ip(src) and valid_ip(dst_dns)): log("[error] Invalid IP."); return
    for i in range(max(1,count)):
        if stop_flag.is_set(): break
        ip, dns = build_dns_packet(src, dst_dns, ttl, qname, qtype, use_edns, do_bit, bufsize_s, nsid, ede_code_s, ede_text)
        try:
            qbytes = bytes(dns)
            l = len(qbytes).to_bytes(2, "big")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.bind((src, 0))
            s.connect((dst_dns, 53))
            s.sendall(l + qbytes)
            hdr = s.recv(2)
            if len(hdr) != 2:
                log(f"[{i+1}] No DNS/TCP response."); s.close()
                if i < count - 1 and interval > 0: time.sleep(interval); continue
            rlen = int.from_bytes(hdr, "big")
            rdata = b""
            while len(rdata) < rlen:
                chunk = s.recv(rlen - len(rdata))
                if not chunk: break
                rdata += chunk
            s.close()
            try:
                ans = DNS(rdata)
                log(f"[{i+1}] DNS/TCP response:"); window["-MS_DNS-"].update(True)
                log(ans.show(dump=True))
            except Exception:
                log(f"[{i+1}] Received {len(rdata)} bytes (parse failed).")
        except Exception as e:
            log(f"[{i+1}] DNS/TCP error: {e}")
        if i < count - 1 and interval > 0: time.sleep(interval)
    log("[info] DNS/TCP sending complete.")

def dns_send_dot(src: str, dst_dns: str, ttl: int, qname: str, qtype: str, count: int, interval: float, timeout: int,
                 use_edns: bool, do_bit: bool, bufsize_s: str, nsid: str, ede_code_s: str, ede_text: str) -> None:
    if not (valid_ip(src) and valid_ip(dst_dns)): log("[error] Invalid IP."); return
    for i in range(max(1,count)):
        if stop_flag.is_set(): break
        ip, dns = build_dns_packet(src, dst_dns, ttl, qname, qtype, use_edns, do_bit, bufsize_s, nsid, ede_code_s, ede_text)
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(timeout)
            raw.bind((src, 0))
            tls = ctx.wrap_socket(raw, server_hostname=None)
            tls.connect((dst_dns, 853))
            qbytes = bytes(dns)
            tls.sendall(len(qbytes).to_bytes(2, "big") + qbytes)
            hdr = tls.recv(2)
            if len(hdr) != 2:
                log(f"[{i+1}] No DoT response."); tls.close()
                if i < count - 1 and interval > 0: time.sleep(interval); continue
            rlen = int.from_bytes(hdr, "big")
            rdata = b""
            while len(rdata) < rlen:
                chunk = tls.recv(rlen - len(rdata))
                if not chunk: break
                rdata += chunk
            tls.close()
            try:
                ans = DNS(rdata)
                log(f"[{i+1}] DoT response:"); window["-MS_DNS-"].update(True)
                log(ans.show(dump=True))
            except Exception:
                log(f"[{i+1}] DoT received {len(rdata)} bytes (parse failed).")
        except Exception as e:
            log(f"[{i+1}] DoT error: {e}")
        if i < count - 1 and interval > 0: time.sleep(interval)
    log("[info] DoT sending complete.")

# =========================
#  ARP Scan
# =========================
def arp_scan(target: str, timeout: int) -> None:
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target)
    log(f"[info] ARP scan {target} on iface {conf.iface or '(default)'}")
    ans, _ = srp(pkt, timeout=timeout, verbose=False)
    if not ans:
        log("[info] No ARP replies."); return
    log("IP\t\tMAC")
    for s, r in ans:
        log(f"{r.psrc}\t{r.hwsrc}")
    window["-MS_ARP-"].update(True)
    log("[info] ARP scan complete.")

# =========================
#  Traceroute (parallel + PTR)
# =========================
def traceroute_any(src: str, dst: str, mode: str, dport: int, max_hops: int, per_timeout: int, probes: int, parallel: bool, do_ptr: bool) -> None:
    if not (valid_ip(src) and valid_ip(dst)): log("[error] Invalid IP."); return
    log(f"[info] Traceroute {mode} from {src} to {dst}, max {max_hops} hops, {probes} probes/TTL, parallel={parallel}")
    if not parallel:
        for ttl in range(1, max(1, max_hops)+1):
            if stop_flag.is_set(): break
            best_dt = None
            best_hop = None
            reached = False
            for _ in range(max(1,probes)):
                pkt = IP(src=src, dst=dst, ttl=ttl)
                if mode == "ICMP": pkt /= ICMP()
                elif mode == "UDP": pkt /= UDP(sport=choose_sport(), dport=dport)
                else: pkt /= TCP(sport=choose_sport(), dport=dport, flags="S")
                t0 = time.time()
                rep = sr1(pkt, timeout=per_timeout, verbose=False)
                dt = int((time.time() - t0)*1000)
                if not rep: continue
                hop = rep.src
                if (best_dt is None) or (dt < best_dt): best_dt, best_hop = dt, hop
                if mode == "ICMP":
                    if hop == dst: reached = True
                elif mode == "UDP":
                    if hop == dst and rep.haslayer(ICMP) and rep.getlayer(ICMP).type == 3: reached = True
                else:
                    if rep.haslayer(TCP) and hop == dst:
                        fl = rep.getlayer(TCP).flags
                        if (fl & 0x12) or (fl & 0x04): reached = True
            if best_hop is None:
                log(f"{ttl}\t*\t(timeout)")
            else:
                rname = ""
                if do_ptr:
                    try: rname = socket.gethostbyaddr(best_hop)[0]
                    except Exception: rname = ""
                log(f"{ttl}\t{best_hop}{(' ('+rname+')') if rname else ''}\t{best_dt} ms")
            if reached:
                if mode == "TCP": window["-MS_TRTCP-"].update(True)
                log("[info] Reached destination."); break
    else:
        sent = []
        for ttl in range(1, max(1, max_hops)+1):
            for _ in range(max(1,probes)):
                pkt = IP(src=src, dst=dst, ttl=ttl)
                if mode == "ICMP": pkt /= ICMP()
                elif mode == "UDP": pkt /= UDP(sport=choose_sport(), dport=dport)
                else: pkt /= TCP(sport=choose_sport(), dport=dport, flags="S")
                sent.append((ttl, pkt))
        start = time.time()
        answered, _ = sr([p for _,p in sent], timeout=per_timeout, verbose=False)
        best_by_ttl = {}
        reached = False
        for s, r in (answered or []):
            ttl = s.ttl
            hop = r.src
            dt = int((time.time() - start)*1000)
            if ttl not in best_by_ttl or dt < best_by_ttl[ttl][1]:
                best_by_ttl[ttl] = (hop, dt)
            if s[IP].dst == hop:
                if mode == "ICMP":
                    if hop == dst: reached = True
                elif mode == "UDP":
                    if hop == dst and r.haslayer(ICMP) and r.getlayer(ICMP).type == 3: reached = True
                else:
                    if r.haslayer(TCP) and hop == dst:
                        fl = r.getlayer(TCP).flags
                        if (fl & 0x12) or (fl & 0x04): reached = True
        for ttl in range(1, max(1, max_hops)+1):
            if ttl in best_by_ttl:
                hop, dt = best_by_ttl[ttl]
                rname = ""
                if do_ptr:
                    try: rname = socket.gethostbyaddr(hop)[0]
                    except Exception: rname = ""
                log(f"{ttl}\t{hop}{(' ('+rname+')') if rname else ''}\t{dt} ms")
            else:
                log(f"{ttl}\t*\t(timeout)")
        if reached and mode == "TCP":
            window["-MS_TRTCP-"].update(True)
        log("[info] Traceroute complete.")

# -------- Live Sniffer with realtime counters & rotation & index --------
def _open_new_writer(base: Path, idx: int):
    fname = base.with_name(f"{base.name}_{idx:03d}.pcap")
    return PcapWriter(str(fname), append=True, sync=True)

def start_live_sniff(filter_exp: str, roll_sec: int, roll_mb: int, timeout_s: int):
    global _live_writer, _live_rotate_next, _live_roll_sec, _live_roll_mb, _live_base
    global sniff_running, _last_sniff, last_sec_count, proto_counts, pcap_index
    sniff_running = True
    stop_flag.clear()
    _last_sniff = []
    proto_counts = Counter()
    pps_hist.clear()
    last_sec_count = 0
    pcap_index = []
    _live_roll_sec = max(0, int(roll_sec))
    _live_roll_mb = max(0, int(roll_mb))
    _live_base = Path(f"live_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    idx = 0
    bytes_written = 0
    chunk_start_ts = time.time()
    _live_writer = _open_new_writer(_live_base, idx) if (roll_sec>0 or roll_mb>0) else None
    _live_rotate_next = (datetime.now() + timedelta(seconds=_live_roll_sec)) if _live_roll_sec else None
    chunk_count = 0

    def finalize_chunk():
        nonlocal idx, bytes_written, chunk_start_ts, chunk_count
        if _live_writer is None: return
        entry = {
            "file": f"{_live_base.name}_{idx:03d}.pcap",
            "packets": chunk_count,
            "bytes": bytes_written,
            "start": chunk_start_ts,
            "end": time.time()
        }
        pcap_index.append(entry)
        index_path = _live_base.with_name(f"{_live_base.name}_index.json")
        summary = {
            "created": time.time(),
            "chunks": pcap_index,
            "total_packets": sum(e["packets"] for e in pcap_index),
            "total_bytes": sum(e["bytes"] for e in pcap_index),
        }
        try:
            with open(index_path, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2)
        except Exception as e:
            log(f"[warn] index write failed: {e}")

    def on_packet(p):
        nonlocal idx, bytes_written, chunk_start_ts, chunk_count
        if stop_flag.is_set():
            return False
        try:
            if IP in p:
                proto = p[IP].proto
                if proto == 6: proto_counts["TCP"] += 1
                elif proto == 17: proto_counts["UDP"] += 1
                elif proto == 1: proto_counts["ICMP"] += 1
                else: proto_counts["Other"] += 1
            else:
                proto_counts["Other"] += 1
        except Exception:
            pass
        if len(_last_sniff) < 500:
            _last_sniff.append(p)
        if _live_writer is not None:
            _live_writer.write(p)
            size = len(bytes(p)) if hasattr(p, "original") else len(bytes(p))
            bytes_written += size
            chunk_count += 1
            if _live_rotate_next and datetime.now() >= _live_rotate_next:
                try: _live_writer.close()
                except Exception: pass
                finalize_chunk()
                idx += 1; _live_writer = _open_new_writer(_live_base, idx)
                _live_rotate_next = datetime.now() + timedelta(seconds=_live_roll_sec)
                bytes_written = 0; chunk_count = 0; chunk_start_ts = time.time()
            if _live_roll_mb and bytes_written >= _live_roll_mb * 1024 * 1024:
                try: _live_writer.close()
                except Exception: pass
                finalize_chunk()
                idx += 1; _live_writer = _open_new_writer(_live_base, idx)
                _live_rotate_next = datetime.now() + timedelta(seconds=_live_roll_sec) if _live_roll_sec else None
                bytes_written = 0; chunk_count = 0; chunk_start_ts = time.time()

    def _sniff_thread():
        try:
            sniff(filter=filter_exp or None, prn=on_packet,
                  timeout=timeout_s if timeout_s>0 else None,
                  iface=conf.iface or None, store=False, stop_filter=lambda x: stop_flag.is_set())
        except Exception as e:
            window.write_event_value("-LIVE_ERR-", str(e))
        finally:
            if _live_writer:
                try:
                    _live_writer.close()
                except Exception: pass
            sniff_running = False
            window.write_event_value("-LIVE_DONE-", None)

    def _ticker_thread():
        global last_sec_count
        last = time.time()
        while sniff_running and not stop_flag.is_set():
            time.sleep(0.2)
            now = time.time()
            if now - last >= 1.0:
                pps_hist.append(last_sec_count)
                last_sec_count = 0
                window.write_event_value("-LIVE_TICK-", None)
                last = now

    def _counter_hook(p):
        global last_sec_count
        last_sec_count += 1

    threading.Thread(target=_sniff_thread, daemon=True).start()
    threading.Thread(target=_ticker_thread, daemon=True).start()
    threading.Thread(target=lambda: sniff(filter=filter_exp or None, prn=_counter_hook, store=False,
                                          iface=conf.iface or None,
                                          stop_filter=lambda x: stop_flag.is_set(),
                                          timeout=timeout_s if timeout_s>0 else None),
                     daemon=True).start()

def stop_live_sniff():
    stop_flag.set()

def save_last_sniff(path_str: str) -> None:
    global _last_sniff
    if not _last_sniff:
        log("[warn] No packets to save."); return
    out = Path(path_str or f"sniff_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap")
    wrpcap(str(out), _last_sniff)
    log(f"[info] Saved {len(_last_sniff)} packets to {out}")

def export_csv(path_str: str) -> None:
    out = Path(path_str or f"metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
    try:
        with open(out, "w", encoding="utf-8") as f:
            f.write("metric,value\n")
            f.write(f"TCP,{proto_counts.get('TCP',0)}\n")
            f.write(f"UDP,{proto_counts.get('UDP',0)}\n")
            f.write(f"ICMP,{proto_counts.get('ICMP',0)}\n")
            f.write(f"Other,{proto_counts.get('Other',0)}\n")
            f.write("pps_history,seconds_ago:value ...\n")
            for idx, val in enumerate(list(pps_hist)):
                f.write(f"pps_{idx},{val}\n")
        log(f"[info] Exported CSV -> {out}")
    except Exception as e:
        log(f"[error] CSV export failed: {e}")

# =========================
#  HTTP Server (FastAPI + Uvicorn)
# =========================
def _make_app(doc_root: Optional[str]) -> "FastAPI":
    app = FastAPI(title="Scapy L2/L3 Toolkit helper", version="9.3")

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "ts": datetime.utcnow().isoformat() + "Z"}

    @app.get("/echo", response_class=PlainTextResponse)
    def echo(q: str = ""):
        return q or "pong"

    @app.get("/time")
    def time_now():
        return JSONResponse({"now": datetime.utcnow().isoformat() + "Z"})

    if doc_root and _HAS_STATIC and Path(doc_root).exists():
        app.mount("/static", StaticFiles(directory=doc_root), name="static")

    @app.get("/", response_class=PlainTextResponse)
    def index():
        lines = [
            "Scapy L2/L3 Toolkit helper",
            "Endpoints:",
            "  GET /healthz  -> {'status':'ok'}",
            "  GET /echo?q=hello",
            "  GET /time     -> UTC time JSON",
            "  /static/*     -> serve files (if doc_root set)",
        ]
        return "\n".join(lines)

    return app

def start_http_server(port: int, bind_host: str = "0.0.0.0", doc_root: Optional[str] = None):
    global _http_thread, _http_stop, _http_port, _http_bind, _http_ok, _http_server

    if not (_HAS_FASTAPI and _HAS_UVICORN):
        msg = ("FastAPI / Uvicorn が見つかりません。\n"
               "  pip install fastapi uvicorn\n"
               "を実行してから再試行してください。")
        try:
            sg.popup_error(msg, title="Missing dependency")
        except Exception:
            log(msg)
        return

    stop_http_server()  # ensure previous is stopped
    _http_stop = threading.Event()

    app = _make_app(doc_root)
    config = uvicorn.Config(
        app=app,
        host=bind_host,
        port=int(port),
        log_level="warning",
        access_log=False,
        timeout_keep_alive=5,
    )
    server = uvicorn.Server(config)
    _http_server = server

    def _run():
        try:
            server.run()
        except Exception as e:
            log(f"[http:uvicorn] {e}")
        finally:
            log("[http] stopped.")

    _http_thread = threading.Thread(target=_run, daemon=True)
    _http_thread.start()

    _http_port, _http_bind = int(port), bind_host
    time.sleep(0.2)
    _http_ok = _check_http_health(bind_host, int(port))
    update_ports_label()
    if _http_ok:
        log(f"[http] FastAPI on http://{bind_host}:{port}  (health OK)")
    else:
        log(f"[http] FastAPI on http://{bind_host}:{port}  (health NG)")

def stop_http_server():
    global _http_port, _http_bind, _http_ok, _http_thread, _http_server
    try:
        if _http_server is not None:
            _http_server.should_exit = True
        if _http_thread is not None and _http_thread.is_alive():
            _http_thread.join(timeout=2.0)
    except Exception:
        pass
    _http_thread = None
    _http_server = None
    _http_port, _http_bind = None, None
    _http_ok = False
    update_ports_label()

# =========================
#  UDP Echo Server
# =========================
def start_udp_echo(port: int, bind_host: str = "0.0.0.0"):
    """Start a UDP echo server."""
    global _udp_thread, _udp_stop, _udp_port, _udp_bind, _udp_ok, _udp_sock
    stop_udp_echo()
    _udp_stop = threading.Event()

    def _echo():
        global _udp_sock
        try:
            _udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            _udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            _udp_sock.bind((bind_host, int(port)))
            _udp_sock.settimeout(0.5)
            log(f"[udp] Echo server on {bind_host}:{port}")
            while not _udp_stop.is_set():
                try:
                    data, addr = _udp_sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except Exception as e:
                    log(f"[udp:error] {e}")
                    break
                try:
                    _udp_sock.sendto(data, addr)
                except Exception as e:
                    log(f"[udp:send-error] {e}")
                    break
        except Exception as e:
            log(f"[udp:error] {e}")
        finally:
            try:
                if _udp_sock:
                    _udp_sock.close()
            except Exception:
                pass
            _udp_sock = None
            log("[udp] stopped.")

    _udp_thread = threading.Thread(target=_echo, daemon=True)
    _udp_thread.start()
    _udp_port, _udp_bind = int(port), bind_host
    time.sleep(0.1)
    _udp_ok = _check_udp_echo_alive(bind_host, int(port))
    update_ports_label()

def stop_udp_echo():
    global _udp_port, _udp_bind, _udp_ok, _udp_stop, _udp_thread, _udp_sock
    try:
        if _udp_stop and not _udp_stop.is_set():
            _udp_stop.set()
        if _udp_sock:
            _udp_sock.close()
    except Exception:
        pass
    _udp_port, _udp_bind = None, None
    _udp_ok = False
    _udp_thread = None
    _udp_sock = None
    update_ports_label()

# =========================
#  Event loop
# =========================
if not is_admin():
    sg.popup("Raw sockets need admin/root privileges.\nSome operations may fail. Run as Administrator (Windows) or with sudo.", title="Permission warning")

window["-STATUS-"].update("Ready.")
apply_language()
update_ports_label()
log(f"[info] GUI backend: {_GUI_BACKEND}")

def run_async(fn, *args, **kwargs):
    def _wrap():
        try: fn(*args, **kwargs)
        except Exception as e: log(f"[error] {e}")
        finally:
            window.write_event_value("-FINISH-", None)
    threading.Thread(target=_wrap, daemon=True).start()

def update_mini_bars():
    rc = {"TCP": proto_counts.get("TCP",0),
          "UDP": proto_counts.get("UDP",0),
          "ICMP": proto_counts.get("ICMP",0),
          "Other": proto_counts.get("Other",0)}
    total = sum(rc.values())
    lines = [
        bar_row("TCP", rc["TCP"], total),
        bar_row("UDP", rc["UDP"], total),
        bar_row("ICMP", rc["ICMP"], total),
        bar_row("Other", rc["Other"], total),
    ]
    window["-MINIBAR-"].update("\n".join(lines))

while True:
    event, values = window.read(timeout=200)
    if event in (sg.WIN_CLOSED, "-EXIT-", "Exit"):
        break
    if event == "-CANCEL-":
        stop_flag.set(); set_status("Cancelling…"); continue
    if event == "-LANG-":
        new_lang = values.get("-LANG-", "JP")
        if new_lang in LP:
            LANG = new_lang  # type: ignore
            apply_language()
        continue

    src = values.get("-SRC-", "").strip()
    dst = values.get("-DST-", "").strip()
    ttl = ttl_from(values)
    timeout = timeout_from(values)
    try: retries = max(0, int(values["-RETRIES-"]))
    except Exception: retries = 0

    # realtime UI ticks
    if event == "-LIVE_TICK-":
        window["-SPARK-"].update(make_sparkline(list(pps_hist), 60))
        rc = {"TCP": proto_counts.get("TCP",0),
              "UDP": proto_counts.get("UDP",0),
              "ICMP": proto_counts.get("ICMP",0),
              "Other": proto_counts.get("Other",0)}
        window["-RATIO-"].update(ratio_bar(rc, 40))
        update_mini_bars()
        continue
    if event == "-LIVE_ERR-":
        log(f"[error] Live sniff: {values[event]}"); continue
    if event == "-LIVE_DONE-":
        set_status("Ready."); continue

    # start banner
    if event in ("-PING1-","-PING2-","-SYN1-","-SYN3-","-TCPSCAN-","-ROUTES-","-GETMAC-","-XMAS-","-IKE-","-PCAP-",
                 "-CP_SEND-","-LIST_IFACES-","-USE_IFACE-","-DNS_SEND-","-ARP_SCAN-","-TR_START-",
                 "-SNIFF_LIVE-","-SNIFF_STOP-","-SNIFF_SAVE-","-CSV_EXPORT-","-MS_HINTS-","-MS_DNS_SAMPLE-",
                 "-HTTP_START-","-HTTP_STOP-","-UDP_START-","-UDP_STOP-","-CP_SAMPLE-","-DNS_EDE_HELP-",
                 "-BTN_ENV-","-BTN_NET-"):
        window["-PROG-"].update(current_count=0, max=100)
        set_status("Running..."); log(f"== {event} ==")

    # NEW: Env/Versions + Network Info
    if event == "-BTN_ENV-":
        run_async(show_env_versions_popup)

    elif event == "-BTN_NET-":
        run_async(show_network_info_popup)

    elif event == "-LIST_IFACES-":
        run_async(list_ifaces)

    elif event == "-USE_IFACE-":
        run_async(set_iface, values.get("-IFACE-", ""))

    elif event == "-IFACE_PICK-":
        sel = values.get("-IFACE_PICK-")
        if sel: run_async(set_iface, sel)

    elif event == "-IFACE_REFRESH-":
        try: window["-IFACE_PICK-"].update(values=list_iface_names())
        except Exception as e: log(f"[error] refresh ifaces: {e}")

    elif event == "-SRV_BIND_REFRESH-":
        try: window["-SRV_BIND-"].update(values=bind_candidates(), value="0.0.0.0")
        except Exception as e: log(f"[error] refresh binds: {e}")

    elif event == "-PING1-":
        if not (valid_ip(src) and valid_ip(dst)): sg.popup_error("Invalid IPv4 address.", title="Input error"); continue
        run_async(ping_one_way, src, dst, ttl)

    elif event == "-PING2-":
        if not (valid_ip(src) and valid_ip(dst)): sg.popup_error("Invalid IPv4 address.", title="Input error"); continue
        run_async(ping_two_way, src, dst, ttl, timeout, retries)

    elif event == "-SYN1-":
        if not (valid_ip(src) and not valid_ip(dst)):  # typo-proof; keep original behavior
            pass
        if not (valid_ip(src) and valid_ip(dst)): sg.popup_error("Invalid IPv4 address.", title="Input error"); continue
        try: dport = int(values["-DPORT-"])
        except Exception: sg.popup_error("Invalid TCP dport.", title="Input error"); continue
        run_async(syn_one_way, src, dst, ttl, dport)

    elif event == "-SYN3-":
        if not (valid_ip(src) and valid_ip(dst)): sg.popup_error("Invalid IPv4 address.", title="Input error"); continue
        try: dport = int(values["-DPORT-"])
        except Exception: sg.popup_error("Invalid TCP dport.", title="Input error"); continue
        run_async(syn_three_way, src, dst, ttl, dport, timeout, retries)

    elif event == "-TCPSCAN-":
        if not (valid_ip(src) and valid_ip(dst)): sg.popup_error("Invalid IPv4 address.", title="Input error"); continue
        ports = parse_port_range(values["-SCANRANGE-"])
        run_async(tcp_scan, src, dst, ttl, timeout, retries, ports)

    elif event == "-ROUTES-":
        run_async(show_routes)

    elif event == "-GETMAC-":
        if not (valid_ip(src) and valid_ip(dst)): sg.popup_error("Invalid IPv4 address.", title="Input error"); continue
        run_async(get_macs, src, dst)

    elif event == "-XMAS-":
        if not (valid_ip(src) and valid_ip(dst)): sg.popup_error("Invalid IPv4 address.", title="Input error"); continue
        try: xport = int(values["-XPORT-"])
        except Exception: sg.popup_error("Invalid Xmas dport.", title="Input error"); continue
        run_async(xmas_scan, src, dst, ttl, xport, timeout)

    elif event == "-IKE-":
        if not (valid_ip(src) and valid_ip(dst)): sg.popup_error("Invalid IPv4 address.", title="Input error"); continue
        run_async(ike_probe, src, dst, ttl, timeout, retries)

    elif event == "-PCAP-":
        pcap_file = values["-PCAP_FILE-"]
        if not pcap_file: sg.popup_error("Choose a .pcap / .pcapng file.", title="Input error"); continue
        rewrite = bool(values["-REWRITEIP-"]); do_l2 = bool(values["-SENDL2-"]); do_l3 = bool(values["-SENDL3-"])
        if not (do_l2 or do_l3): sg.popup_error("Select at least one of: Send L2 / Send L3.", title="Input error"); continue
        try:
            rep = int(values["-PCAP_COUNT-"]); intr = float(values["-PCAP_INTERVAL-"])
            use_fast = bool(values["-FAST-"]); pps = int(values["-FAST_PPS-"] or "0")
        except Exception:
            sg.popup_error("Invalid send parameters.", title="Input error"); continue
        run_async(send_pcap, src, dst, Path(pcap_file), rewrite, do_l2, do_l3, rep, intr, use_fast, pps)

    elif event == "-CP_SEND-":
        run_async(
            send_custom_payload,
            src, dst, ttl, values["-CP_PROTO-"],
            values["-CP_SPORT-"], values["-CP_DPORT-"],
            values["-CP_DATA-"], bool(values["-CP_HEX-"]),
            values["-CP_COUNT-"], values["-CP_INTERVAL-"],
            bool(values["-CP_L2-"])
        )

    elif event == "-CP_SAMPLE-":
        window["-CP_DATA-"].update("Hello Wireshark! v9.3 🧪"); window["-CP_HEX-"].update(False)
        log("[info] Sample payload inserted.")

    elif event == "-DNS_EDE_HELP-":
        help_txt = "\n".join([f"{k}: {v}" for k,v in sorted(EDE_MAP.items())])
        sg.popup_scrolled(help_txt, title="EDE Codes (RFC 8914 subset)")

    elif event == "-DNS_SEND-":
        if not (valid_ip(src) and valid_ip(values["-DNS_DST-"])): sg.popup_error("Invalid IP.", title="Input error"); continue
        try:
            cnt = int(values["-DNS_COUNT-"]); intr = float(values["-DNS_INTERVAL-"]); buf = values["-DNS_BUFSZ-"]
            use_edns = bool(values["-DNS_EDNS-"]); do = bool(values["-DNS_DO-"])
            nsid = values["-DNS_NSID-"]; ede_c = values["-DNS_EDE_CODE-"]; ede_t = values["-DNS_EDE_TEXT-"]
            trans = values["-DNS_TRAN-"]
        except Exception: sg.popup_error("Invalid DNS params.", title="Input error"); continue
        if trans == "UDP":
            run_async(dns_send_udp, src, values["-DNS_DST-"], ttl, values["-DNS_QNAME-"], values["-DNS_QTYPE-"], cnt, intr, timeout, use_edns, do, buf, nsid, ede_c, ede_t)
        elif trans == "TCP":
            run_async(dns_send_tcp, src, values["-DNS_DST-"], ttl, values["-DNS_QNAME-"], values["-DNS_QTYPE-"], cnt, intr, timeout, use_edns, do, buf, nsid, ede_c, ede_t)
        else:
            run_async(dns_send_dot, src, values["-DNS_DST-"], ttl, values["-DNS_QNAME-"], values["-DNS_QTYPE-"], cnt, intr, timeout, use_edns, do, buf, nsid, ede_c, ede_t)

    elif event == "-ARP_SCAN-":
        try: arp_to = values["-ARP_TARGET-"].strip(); arp_timeout = max(1, int(values["-ARP_TIMEOUT-"]))
        except Exception: sg.popup_error("Invalid ARP inputs.", title="Input error"); continue
        run_async(arp_scan, arp_to, arp_timeout)

    elif event == "-TR_START-":
        try:
            mx = max(1, int(values["-TR_MAX-"])); pt = max(1, int(values["-TR_TIMEOUT-"]))
            pr = max(1, int(values["-TR_PROBES-"]))
            mode = values["-TR_MODE-"]; dport = int(values["-TR_DPORT-"] or "33434")
            par = bool(values["-TR_PARALLEL-"]); doptr = bool(values["-TR_PTR-"])
        except Exception: sg.popup_error("Invalid traceroute inputs.", title="Input error"); continue
        if not (valid_ip(src) and valid_ip(dst)): sg.popup_error("Invalid IPv4 address.", title="Input error"); continue
        run_async(traceroute_any, src, dst, mode, dport, mx, pt, pr, par, doptr)

    elif event == "-SNIFF_LIVE-":
        try:
            filt = values["-SNIF_FILTER-"]; roll_sec = int(values["-SNIF_ROLL_SEC-"] or "0"); roll_mb = int(values["-SNIF_ROLL_MB-"] or "0")
            to = int(values["-SNIF_TIMEOUT-"] or "0")
        except Exception: sg.popup_error("Invalid live sniff params.", title="Input error"); continue
        run_async(start_live_sniff, filt, roll_sec, roll_mb, to)

    elif event == "-SNIFF_STOP-":
        stop_live_sniff()

    elif event == "-SNIFF_SAVE-":
        run_async(save_last_sniff, values["-SNIF_OUT-"])

    elif event == "-CSV_EXPORT-":
        run_async(export_csv, values["-CSV_OUT-"])

    elif event == "-MS_HINTS-":
        lang = values.get("-HINT_LANG-", "JP")
        txt = '🟢 Beginner:\n- Ping 2-way → verify basic reachability\n- DNS A with and without EDNS/DO; observe OPT RR and DO bit\n\n🟡 Intermediate:\n- SYN 3-way / TCP Scan to see state transitions\n- ARP Scan to discover local hosts\n\n🔴 Advanced:\n- Traceroute(TCP): compare SYN/ACK vs RST when reaching dest\n- Custom Payload: craft bytes and verify in Wireshark\n- DoT (853/tcp): compare TLS vs plaintext DNS' if lang == "EN" else '🟢 初級:\n- Ping 2-way で疎通確認\n- DNS A を EDNS/DO あり/なしで比較（OPT/DO ビットを観察）\n\n🟡 中級:\n- SYN 3-way / TCP Scan で状態遷移を体験\n- ARP Scan で同一セグメントのホスト観察\n\n🔴 上級:\n- Traceroute(TCP) で SYN/ACK と RST の違い\n- Custom Payload を投げて Wireshark で可視化\n- DoT（853/tcp）で TLS と平文 DNS の違いを比較'
        sg.popup_scrolled(txt, title=f"Missions Hints ({lang})")

    elif event == "-MS_DNS_SAMPLE-":
        window["-DNS_QNAME-"].update("dnssec-failed.org")
        window["-DNS_QTYPE-"].update("A")
        window["-DNS_EDNS-"].update(True)
        window["-DNS_DO-"].update(True)
        log("[info] Sample DNS task prefilled (dnssec-failed.org, DO=1).")

    elif event == "-HTTP_START-":
        try:
            bh = values["-SRV_BIND-"] or "0.0.0.0"
            prt = int(values["-HTTP_PORT-"] or "8000")
            root = values["-HTTP_ROOT-"] or os.getcwd()
        except Exception:
            sg.popup_error("Invalid HTTP parameters.", title="Input error"); continue
        run_async(start_http_server, prt, bh, root)

    elif event == "-HTTP_STOP-":
        run_async(stop_http_server)

    elif event == "-UDP_START-":
        try:
            bh = values["-SRV_BIND-"] or "0.0.0.0"
            prt = int(values["-UDP_PORT-"] or "9999")
        except Exception:
            sg.popup_error("Invalid UDP parameters.", title="Input error"); continue
        run_async(start_udp_echo, prt, bh)

    elif event == "-UDP_STOP-":
        run_async(stop_udp_echo)

    elif event == "-FINISH-":
        set_status("Ready."); window["-PROG-"].update(current_count=100)

window.close()
