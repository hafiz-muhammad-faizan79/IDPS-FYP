"""
network_monitor.py
==================
CyGuardian-X — Network Monitoring Engine

TWO MODES (controlled by USE_REAL_CAPTURE below):
  False → Simulated realistic traffic  (no sudo needed, works now)
  True  → Real Scapy packet capture    (needs: sudo venv/bin/python -m uvicorn ...)

Your interface: wlp0s20f3  (192.168.1.107)
"""

import time
import random
import threading
import asyncio
import collections
from datetime import datetime
from typing import List, Dict, Any

# ── Toggle this when you're ready for real capture ──────────────
USE_REAL_CAPTURE = True          # False = simulated | True = real Scapy
INTERFACE        = "wlp0s20f3"   # your WiFi interface
MY_IP            = "172.20.10.2"
# ────────────────────────────────────────────────────────────────

if USE_REAL_CAPTURE:
    try:
        from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
        SCAPY_AVAILABLE = True
    except ImportError:
        SCAPY_AVAILABLE = False
        print("[WARN] Scapy not available — falling back to simulated mode")
        USE_REAL_CAPTURE = False
else:
    SCAPY_AVAILABLE = False

import psutil

# ── Signature Rules Engine ─────────────────────────────────────
try:
    from signature_engine import match_packet, start_signature_engine
    SIG_ENGINE_AVAILABLE = True
except ImportError:
    SIG_ENGINE_AVAILABLE = False
    print("[WARN] Signature engine not available")
import queue

# ── Packet DB write queue (non-blocking) ──────────────────────
_packet_queue = queue.Queue(maxsize=5000)

def _db_writer():
    """Background thread — drains packet queue into PostgreSQL."""
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from database import SessionLocal
    from models.network import CapturedPacket

    BATCH_SIZE = 50   # write in batches for efficiency
    batch = []

    while True:
        try:
            pkt_data = _packet_queue.get(timeout=2)
            batch.append(pkt_data)
            if len(batch) >= BATCH_SIZE:
                _flush_batch(batch, SessionLocal, CapturedPacket)
                batch = []
        except queue.Empty:
            if batch:
                _flush_batch(batch, SessionLocal, CapturedPacket)
                batch = []

def _flush_batch(batch, SessionLocal, CapturedPacket):
    db = SessionLocal()
    try:
        db.bulk_insert_mappings(CapturedPacket, batch)
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"[DB] Packet write error: {e}")
    finally:
        db.close()

# ══════════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════════
PROTOCOLS   = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS"]
CONN_STATUS = ["Established", "Established", "Established", "Suspicious", "Blocked"]
ATTACK_TYPES = [
    "DDoS Attempt", "Port Scanning", "Brute Force",
    "SQL Injection", "Malware Signature", "Traffic Spike",
    "SYN Flood", "DNS Tunneling", "ARP Spoofing",
]
LOG_EVENTS  = ["PORT_SCAN","BRUTE_FORCE","DDOS","SQL_INJECT","BLOCKED","ALLOWED","FLAGGED","ARP_SPOOF","DNS_TUNNEL"]
LOG_ACTIONS = ["BLOCKED","ALLOWED","FLAGGED","LOGGED","ALERTED","QUARANTINED"]
LOG_STATUS  = ["SUCCESS","WARNING","CRITICAL","INFO"]

KNOWN_BAD_IPS = [
    "185.220.101.47","194.165.16.78","103.75.190.12",
    "77.83.246.90","91.108.4.200","5.188.206.14",
]

def _rip():
    return f"{random.randint(10,220)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def _ts():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]

def _fullts():
    return datetime.now().isoformat(timespec="seconds")

# ══════════════════════════════════════════════════════════════
# SHARED STATE  (thread-safe via lock)
# ══════════════════════════════════════════════════════════════
class MonitorState:
    def __init__(self):
        self.lock = threading.Lock()

        # Rolling counters
        self.total_packets   = 1_482_301
        self.total_bytes     = 0
        self.pps_history     = collections.deque([500]*60, maxlen=60)  # 60s window
        self.bw_history      = collections.deque([300]*60, maxlen=60)

        # Current tick values
        self.pps        = 2847
        self.bandwidth  = 342    # Mbps
        self.upload     = 128    # Mbps
        self.download   = 214    # Mbps
        self.active_connections = 1247

        # Protocol distribution  (%)
        self.proto_dist = {"TCP":45,"UDP":22,"ICMP":8,"HTTP":12,"HTTPS":13}

        # Traffic type split (%)
        self.traffic_type = {
            "Internal":42,"External":33,"Suspicious":15,"Blocked":10
        }

        # Rolling log (last 200 entries)
        self.logs: collections.deque = collections.deque(maxlen=200)

        # Active connections list
        self.connections: List[Dict] = []

        # Active alerts (last 20)
        self.alerts: List[Dict] = []

        # System health
        self.cpu     = 42
        self.mem     = 67
        self.pkt_loss = 2
        self.latency  = 18

        # Packet counter for current second
        self._tick_packets = 0
        self._tick_bytes   = 0

        # Counters for protocol buckets
        self.proto_counts = collections.defaultdict(int)

        # Threat counter
        self.threats_blocked = 0
        self.threats_detected = 0

        # WebSocket subscriber set
        self.subscribers = set()

    # ── helpers ──────────────────────────────────────────────
    def add_log(self, event, ip, action, status, detail=""):
        entry = {
            "time":   _ts(),
            "fullts": _fullts(),
            "event":  event,
            "ip":     ip,
            "action": action,
            "status": status,
            "detail": detail,
        }
        with self.lock:
            self.logs.appendleft(entry)
        return entry

    def add_alert(self, severity, src_ip, alert_type, desc):
        alert = {
            "id":       int(time.time()*1000) + random.randint(0,999),
            "time":     _ts(),
            "severity": severity,
            "srcIp":    src_ip,
            "type":     alert_type,
            "desc":     desc,
            "glowing":  severity == "Critical",
        }
        with self.lock:
            self.alerts.insert(0, alert)
            if len(self.alerts) > 20:
                self.alerts.pop()
            if severity in ("High","Critical"):
                self.threats_detected += 1
        return alert

    def add_connection(self, conn):
        with self.lock:
            self.connections.insert(0, conn)
            if len(self.connections) > 60:
                self.connections.pop()

    def snapshot(self) -> Dict[str, Any]:
        """Return a complete JSON-serialisable snapshot of current state."""
        with self.lock:
            return {
                "timestamp":    _fullts(),
                "stats": {
                    "total_packets":      self.total_packets,
                    "pps":                self.pps,
                    "bandwidth":          self.bandwidth,
                    "upload":             self.upload,
                    "download":           self.download,
                    "active_connections": self.active_connections,
                    "threats_detected":   self.threats_detected,
                    "threats_blocked":    self.threats_blocked,
                },
                "proto_dist":   dict(self.proto_dist),
                "traffic_type": dict(self.traffic_type),
                "pps_history":  list(self.pps_history),
                "bw_history":   list(self.bw_history),
                "health": {
                    "cpu":      self.cpu,
                    "mem":      self.mem,
                    "pkt_loss": self.pkt_loss,
                    "latency":  self.latency,
                },
                "connections": list(self.connections)[:40],
                "alerts":      list(self.alerts)[:20],
                "logs":        list(self.logs)[:50],
            }


# Global singleton
state = MonitorState()


# ══════════════════════════════════════════════════════════════
# ── MODE 1: SIMULATED ENGINE ──────────────────────────────────
# ══════════════════════════════════════════════════════════════
def _sim_connection(cid: int) -> Dict:
    status = random.choice(CONN_STATUS)
    proto  = random.choice(PROTOCOLS)
    port   = random.choice([80,443,22,3306,8080,53,25,110,8443,3389])
    src    = random.choice(KNOWN_BAD_IPS) if status != "Established" else _rip()
    return {
        "id":       cid,
        "srcIp":    src,
        "dstIp":    MY_IP if random.random() < 0.6 else _rip(),
        "protocol": proto,
        "port":     port,
        "status":   status,
        "data":     f"{random.randint(1,9999)} KB",
        "duration": f"{random.randint(0,59)}m {random.randint(0,59)}s",
        "flagged":  status != "Established",
        "timestamp":_fullts(),
    }

def _sim_alert() -> Dict:
    sev  = random.choices(
        ["Info","Low","Medium","High","Critical"],
        weights=[10,20,30,25,15]
    )[0]
    src  = random.choice(KNOWN_BAD_IPS) if sev in ("High","Critical") else _rip()
    typ  = random.choice(ATTACK_TYPES)
    desc_map = {
        "DDoS Attempt":      f"Volumetric flood from {src} — {random.randint(50,500)}K pps detected",
        "Port Scanning":     f"Sequential port probe from {src} — {random.randint(100,1000)} ports scanned",
        "Brute Force":       f"SSH/FTP login attempts from {src} — {random.randint(50,2000)} failures",
        "SQL Injection":     f"SQLi payload detected in HTTP request from {src}",
        "Malware Signature": f"Known malware C2 beacon pattern matched — src {src}",
        "Traffic Spike":     f"Traffic {random.randint(3,15)}x above baseline from {src}",
        "SYN Flood":         f"Incomplete TCP handshakes — {random.randint(10,100)}K SYN packets",
        "DNS Tunneling":     f"Long subdomain queries detected — possible covert channel from {src}",
        "ARP Spoofing":      f"ARP cache poisoning attempt detected on local subnet",
    }
    return state.add_alert(sev, src, typ, desc_map.get(typ,"Anomalous traffic detected"))

def _sim_log() -> Dict:
    event  = random.choice(LOG_EVENTS)
    action = random.choice(LOG_ACTIONS)
    status = random.choices(LOG_STATUS, weights=[40,30,15,15])[0]
    ip     = random.choice(KNOWN_BAD_IPS) if status == "CRITICAL" else _rip()
    detail_map = {
        "PORT_SCAN":   f"Scanned {random.randint(10,500)} ports",
        "BRUTE_FORCE": f"{random.randint(10,2000)} failed attempts",
        "DDOS":        f"{random.randint(10,900)}K pps flood",
        "SQL_INJECT":  "UNION SELECT payload detected",
        "BLOCKED":     "Rule SIG-AUTO triggered",
        "ALLOWED":     "Whitelisted IP",
        "FLAGGED":     "Added to watchlist",
        "ARP_SPOOF":   "ARP cache poisoning attempt",
        "DNS_TUNNEL":  "Encoded data in DNS subdomain",
    }
    return state.add_log(event, ip, action, status, detail_map.get(event,""))


def _simulated_tick():
    """Called every second to update simulated metrics."""
    r = random.random

    with state.lock:
        # Packets
        new_pkts = random.randint(1800, 4500)
        state.total_packets += new_pkts
        state.pps = new_pkts

        # Bandwidth
        bw = random.randint(220, 480)
        up = random.randint(60, 180)
        dn = bw - up
        state.bandwidth = bw
        state.upload    = up
        state.download  = dn

        # Connections
        state.active_connections = random.randint(1100, 1500)

        # Protocol mix
        tcp   = random.randint(35, 55)
        udp   = random.randint(15, 28)
        icmp  = random.randint(4,  12)
        http  = random.randint(7,  18)
        https = 100 - tcp - udp - icmp - http
        state.proto_dist = {"TCP":tcp,"UDP":udp,"ICMP":icmp,"HTTP":http,"HTTPS":max(https,5)}

        # Traffic type
        state.traffic_type = {
            "Internal":  random.randint(35,50),
            "External":  random.randint(28,40),
            "Suspicious":random.randint(10,20),
            "Blocked":   random.randint(5,15),
        }

        # System health (uses real psutil)
        try:
            state.cpu     = int(psutil.cpu_percent(interval=None))
            state.mem     = int(psutil.virtual_memory().percent)
        except Exception:
            state.cpu     = random.randint(25, 80)
            state.mem     = random.randint(50, 80)
        state.pkt_loss = random.randint(0, 4)
        state.latency  = random.randint(6, 45)

        # Rolling history
        state.pps_history.append(new_pkts)
        state.bw_history.append(bw)

    # New random connection
    if random.random() < 0.4:
        conn = _sim_connection(int(time.time()*1000))
        state.add_connection(conn)

    # New log entry
    _sim_log()

    # Occasional alert (30% chance per tick)
    if random.random() < 0.30:
        _sim_alert()
        if random.random() < 0.5:
            with state.lock:
                state.threats_blocked += 1


def _simulated_engine():
    """Background thread — simulates live traffic forever."""
    # Pre-populate connections and logs
    for i in range(40):
        state.add_connection(_sim_connection(i))
    for _ in range(50):
        _sim_log()
    for _ in range(8):
        _sim_alert()

    print(f"[SIM] Simulated network engine started")
    while True:
        _simulated_tick()
        time.sleep(1)


# ══════════════════════════════════════════════════════════════
# ── MODE 2: REAL SCAPY CAPTURE ───────────────────────────────
# ══════════════════════════════════════════════════════════════
def _process_real_packet(pkt):
    """Callback for every captured packet."""
    if not pkt.haslayer("IP"):
        return

    ip_layer = pkt["IP"]
    src      = ip_layer.src
    dst      = ip_layer.dst
    length   = len(pkt)

    if pkt.haslayer("TCP"):
        proto = "TCP"
        port  = pkt["TCP"].dport
    elif pkt.haslayer("UDP"):
        proto = "UDP"
        port  = pkt["UDP"].dport
    elif pkt.haslayer("ICMP"):
        proto = "ICMP"
        port  = 0
    else:
        proto = "OTHER"
        port  = 0

    port_proto_map = {
        80:"HTTP", 443:"HTTPS", 53:"DNS", 22:"SSH",
        21:"FTP", 25:"SMTP", 3306:"MySQL", 5432:"PostgreSQL",
        3389:"RDP", 8080:"HTTP-ALT", 8443:"HTTPS-ALT",
    }
    display_proto = port_proto_map.get(port, proto)

    with state.lock:
        state.total_packets += 1
        state._tick_packets += 1
        state._tick_bytes   += length
        state.proto_counts[display_proto] += 1

    is_bad_ip         = src in KNOWN_BAD_IPS
    is_sensitive_port = port in [22, 23, 3389, 5900, 1433, 3306, 5432]
    status = "Blocked" if is_bad_ip else "Suspicious" if is_sensitive_port else "Established"

    if random.random() < 0.15:
        conn = {
            "id":        int(time.time() * 1000) + random.randint(0, 999),
            "srcIp":     src,
            "dstIp":     dst,
            "protocol":  display_proto,
            "port":      port,
            "status":    status,
            "data":      f"{length} B",
            "duration":  "0m 0s",
            "flagged":   is_bad_ip or is_sensitive_port,
            "timestamp": _fullts(),
        }
        state.add_connection(conn)

    _detect_threats(pkt, src, dst, proto, port)

    # ── Signature Rules Engine matching ───────────────────────
    if SIG_ENGINE_AVAILABLE:
        try:
            payload = ""
            if pkt.haslayer("Raw"):
                try:
                    payload = pkt["Raw"].load.decode("utf-8", errors="ignore")
                except Exception:
                    payload = ""
            match_packet(src, dst, display_proto, port, payload, pkt)
        except Exception as e:
            pass  # never crash the capture thread

    # Store every 10th packet in DB (non-blocking)
    if random.random() < 0.1:
        try:
            _packet_queue.put_nowait({
                "src_ip":   src,
                "dst_ip":   dst,
                "protocol": display_proto,
                "port":     port,
                "length":   length,
                "status":   status,
                "flagged":  is_bad_ip or is_sensitive_port,
            })
        except Exception:
            pass  # queue full — drop packet

def _detect_threats(pkt, src, dst, proto, port=0):
    """Basic real-time threat detection on captured packets."""
    # Known bad IPs
    if src in KNOWN_BAD_IPS:
        state.add_alert("Critical", src, "Malware Signature",
                        f"Packet from known malicious IP {src}")
        state.add_log("BLOCKED", src, "BLOCKED", "CRITICAL",
                     "Known bad IP auto-blocked")
        with state.lock:
            state.threats_blocked += 1
        return

    # SYN flood detection (TCP with SYN flag, no ACK)
    if pkt.haslayer("TCP"):
        tcp = pkt["TCP"]
        if tcp.flags == 0x02:   # SYN only
            state.add_log("PORT_SCAN", src, "FLAGGED", "WARNING",
                         f"SYN to port {tcp.dport}")

    # Port scan — connections to many ports from same IP
    if proto == "TCP" and pkt.haslayer("TCP"):
        port = pkt["TCP"].dport
        if port in [22, 23, 3389, 5900, 1433, 3306]:
            sev = "High" if port in [22, 3389] else "Medium"
            state.add_alert(sev, src, "Port Scanning",
                           f"Connection attempt to sensitive port {port} from {src}")
            state.add_log("PORT_SCAN", src, "FLAGGED", "WARNING",
                         f"Sensitive port {port} accessed")


def _real_stats_updater():
    """Updates per-second stats from real capture counters."""
    while True:
        time.sleep(1)
        with state.lock:
            pps = state._tick_packets
            bw  = int((state._tick_bytes * 8) / 1_000_000)   # bits → Mbps
            state.pps        = pps
            state.bandwidth  = bw
            state.upload     = bw // 3
            state.download   = bw - (bw // 3)
            state._tick_packets = 0
            state._tick_bytes   = 0
            state.pps_history.append(pps)
            state.bw_history.append(bw)

            # Real system stats
            state.cpu      = int(psutil.cpu_percent(interval=None))
            state.mem      = int(psutil.virtual_memory().percent)
            # Real latency via ping
            try:
                import subprocess
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", "1", "8.8.8.8"],
                    capture_output=True, text=True, timeout=2
                )
                for line in result.stdout.split("\n"):
                    if "time=" in line:
                        state.latency = int(float(line.split("time=")[1].split(" ")[0]))
                        break
            except:
                state.latency = random.randint(4, 30)

            # Real active connections via psutil
            conns = psutil.net_connections(kind="inet")
            state.active_connections = len(conns)

            # Real protocol distribution from counts
            total = sum(state.proto_counts.values()) or 1
            state.proto_dist = {
                k: int((v/total)*100)
                for k,v in state.proto_counts.items()
            }


def _real_engine():
    """Start Scapy sniffer + stats updater thread."""
    print(f"[REAL] Starting Scapy capture on {INTERFACE}")
    # Stats updater in background
    t = threading.Thread(target=_real_stats_updater, daemon=True)
    t.start()
    # Scapy blocking sniff
    from scapy.all import sniff
    sniff(iface=INTERFACE, prn=_process_real_packet, store=False)


# ══════════════════════════════════════════════════════════════
# STARTUP — called once from main.py
# ══════════════════════════════════════════════════════════════
def start_monitor():
    """Launch the appropriate engine in a daemon thread."""
    # Start DB writer thread
    db_thread = threading.Thread(target=_db_writer, daemon=True)
    db_thread.start()
    print("[MONITOR] DB writer thread started")

    # Start signature rules engine
    if SIG_ENGINE_AVAILABLE:
        start_signature_engine()

    if USE_REAL_CAPTURE and SCAPY_AVAILABLE:
        t = threading.Thread(target=_real_engine, daemon=True)
    else:
        t = threading.Thread(target=_simulated_engine, daemon=True)
    t.start()
    mode = "REAL CAPTURE" if (USE_REAL_CAPTURE and SCAPY_AVAILABLE) else "SIMULATED"
    print(f"[MONITOR] Engine started — MODE: {mode}")