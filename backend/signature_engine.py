"""
signature_engine.py
===================
CyGuardian-X — Real-time Signature Rules Engine

Loads rules from PostgreSQL and matches them against every live packet.
Supports: Alert, Block (iptables), Drop, Log actions.
Hot-reloads rules every 30 seconds or on demand.
"""

import re
import threading
import time
import subprocess
from typing import List, Dict, Any
from datetime import datetime

# ── Rule cache ─────────────────────────────────────────────────
_rules: List[Dict] = []
_rules_lock = threading.Lock()
_blocked_ips_cache = set()  # IPs already blocked via iptables

# ── Stats ──────────────────────────────────────────────────────
rule_match_counts: Dict[str, int] = {}  # rule_id -> hit count


def load_rules_from_db():
    """Load all enabled signature rules from PostgreSQL."""
    try:
        from database import SessionLocal
        from models.configuration import SignatureRule
        db = SessionLocal()
        rules = db.query(SignatureRule).filter(SignatureRule.enabled == True).all()
        loaded = []
        for r in rules:
            try:
                compiled = re.compile(r.pattern, re.IGNORECASE)
            except re.error:
                compiled = None
            loaded.append({
                "id":       r.id,
                "name":     r.name,
                "category": r.category,
                "severity": r.severity,
                "protocol": r.protocol.upper(),
                "action":   r.action,
                "pattern":  r.pattern,
                "regex":    compiled,
            })
        db.close()
        with _rules_lock:
            _rules.clear()
            _rules.extend(loaded)
        print(f"[SIG ENGINE] Loaded {len(loaded)} active rules from DB")
        return len(loaded)
    except Exception as e:
        print(f"[SIG ENGINE] Rule load error: {e}")
        return 0


def reload_rules():
    """Called externally when rules are updated via API."""
    return load_rules_from_db()


def _rules_auto_reloader():
    """Background thread — reloads rules every 30 seconds."""
    while True:
        time.sleep(30)
        load_rules_from_db()


# ── iptables integration ───────────────────────────────────────
def _block_ip_iptables(ip: str, rule_id: str, rule_name: str):
    """Add iptables DROP rule for IP — requires sudo."""
    if ip in _blocked_ips_cache:
        return  # already blocked
    try:
        # Check if rule already exists
        check = subprocess.run(
            ["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True
        )
        if check.returncode != 0:
            # Rule doesn't exist — add it
            result = subprocess.run(
                ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                _blocked_ips_cache.add(ip)
                print(f"[FIREWALL] Blocked {ip} via iptables — rule {rule_id} ({rule_name})")
            else:
                print(f"[FIREWALL] iptables failed for {ip}: {result.stderr}")
        else:
            _blocked_ips_cache.add(ip)
    except Exception as e:
        print(f"[FIREWALL] iptables error for {ip}: {e}")


def _unblock_ip_iptables(ip: str):
    """Remove iptables DROP rule for IP."""
    try:
        subprocess.run(
            ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, timeout=5
        )
        _blocked_ips_cache.discard(ip)
        print(f"[FIREWALL] Unblocked {ip} via iptables")
    except Exception as e:
        print(f"[FIREWALL] Unblock error for {ip}: {e}")


def _log_rule_match(rule: Dict, src: str, dst: str, proto: str,
                    port: int, payload: str, action_taken: str):
    """Persist rule match to DB."""
    try:
        from database import SessionLocal
        from models.network import NetworkAlert, NetworkLog
        db = SessionLocal()

        # Add alert
        alert = NetworkAlert(
            severity=rule["severity"],
            src_ip=src,
            dst_ip=dst,
            message=f"[{rule['id']}] {rule['name']} — {action_taken}",
            protocol=proto,
            port=port,
        )
        db.add(alert)

        # Add log
        log = NetworkLog(
            status=action_taken.upper(),
            src_ip=src,
            event="SIGNATURE_MATCH",
            result="SUCCESS" if action_taken in ("Block","Drop") else "INFO",
            message=f"Rule {rule['id']} matched: {rule['name']} | {src}→{dst}:{port}",
        )
        db.add(log)

        # Update hit count in DB
        from models.configuration import SignatureRule
        sig = db.query(SignatureRule).filter(SignatureRule.id == rule["id"]).first()
        if sig:
            sig.updated_at = datetime.utcnow()

        db.commit()
        db.close()
    except Exception as e:
        print(f"[SIG ENGINE] Log error: {e}")


# ── Protocol port mapping ──────────────────────────────────────
PROTO_PORT_MAP = {
    "HTTP":  [80, 8080, 8000],
    "HTTPS": [443, 8443],
    "FTP":   [21],
    "SSH":   [22],
    "SMTP":  [25, 587],
    "DNS":   [53],
    "RDP":   [3389],
    "SMB":   [445, 139],
    "MySQL": [3306],
}


def _proto_matches(rule_proto: str, pkt_proto: str, port: int) -> bool:
    """Check if packet protocol matches rule protocol."""
    if rule_proto == "ANY":
        return True
    if rule_proto == pkt_proto:
        return True
    # Check by port
    allowed_ports = PROTO_PORT_MAP.get(rule_proto, [])
    if port in allowed_ports:
        return True
    return False


# ── Main matching function ─────────────────────────────────────
def match_packet(src: str, dst: str, proto: str, port: int,
                 payload: str = "", raw_pkt=None):
    """
    Match a packet against all loaded signature rules.
    Called from network_monitor._process_real_packet() for every packet.
    Returns list of matched rules.
    """
    matched = []

    with _rules_lock:
        rules_snapshot = list(_rules)

    for rule in rules_snapshot:
        # 1. Protocol filter
        if not _proto_matches(rule["protocol"], proto, port):
            continue

        # 2. Pattern matching — against payload or packet summary
        matched_pattern = False

        if rule["regex"] and payload:
            if rule["regex"].search(payload):
                matched_pattern = True

        # 3. Special built-in detectors (for rules without payload)
        if not matched_pattern:
            matched_pattern = _builtin_detector(rule, src, dst, proto, port, raw_pkt)

        if not matched_pattern:
            continue

        # ── Rule matched! ──────────────────────────────────────
        matched.append(rule)
        rule_match_counts[rule["id"]] = rule_match_counts.get(rule["id"], 0) + 1

        action = rule["action"]

        # Execute action
        if action == "Block":
            # Add to in-memory blocked set + iptables
            from network_monitor import state, KNOWN_BAD_IPS
            if src not in KNOWN_BAD_IPS:
                KNOWN_BAD_IPS.append(src)
            with state.lock:
                state.threats_blocked += 1
            _block_ip_iptables(src, rule["id"], rule["name"])

        elif action == "Drop":
            # Mark as threat
            from network_monitor import state
            with state.lock:
                state.threats_detected += 1

        elif action == "Alert":
            from network_monitor import state
            with state.lock:
                state.threats_detected += 1

        # Add alert to live dashboard
        from network_monitor import state
        state.add_alert(
            rule["severity"], src,
            f"[{rule['id']}] {rule['name']}",
            f"Signature matched on {proto}:{port} from {src} → {dst}"
        )

        # Log to DB in background
        threading.Thread(
            target=_log_rule_match,
            args=(rule, src, dst, proto, port, payload, action),
            daemon=True
        ).start()

    return matched


def _builtin_detector(rule: Dict, src: str, dst: str,
                      proto: str, port: int, raw_pkt) -> bool:
    """
    Built-in detectors for rules that can't rely on payload inspection.
    These match based on packet metadata (protocol, port, flags).
    """
    pattern = rule["pattern"].lower()
    rule_id = rule["id"]

    # SYN Flood — SIG-003
    if "syn" in pattern and "flood" in pattern:
        if raw_pkt and raw_pkt.haslayer("TCP"):
            tcp = raw_pkt["TCP"]
            if tcp.flags == 0x02 and port in [80, 443]:
                return False  # normal HTTPS — don't flag
            if tcp.flags == 0x02:
                from network_monitor import state
                # Count SYN packets per second
                with state.lock:
                    if state.pps > 1000:
                        return True
        return False

    # SSH Brute Force — SIG-004
    if "ssh" in pattern and ("brute" in pattern or "failed" in pattern):
        return proto == "TCP" and port == 22

    # FTP Brute Force — SIG-005
    if "ftp" in pattern and ("brute" in pattern or "failed" in pattern):
        return proto == "TCP" and port == 21

    # Nmap SYN Scan — SIG-006
    if "nmap" in pattern or "syn scan" in pattern:
        if raw_pkt and raw_pkt.haslayer("TCP"):
            tcp = raw_pkt["TCP"]
            return tcp.flags == 0x02 and port not in [80, 443, 53]
        return False

    # HTTP Slowloris — SIG-008
    if "slowloris" in pattern:
        return proto == "TCP" and port in [80, 8080] and src != ""

    # Blind SQL Injection — SIG-009
    if "sleep" in pattern or "waitfor" in pattern:
        return "sleep" in (raw_pkt.summary() if raw_pkt else "").lower()

    # RDP Brute Force — SIG-010
    if "rdp" in pattern:
        return proto == "TCP" and port == 3389

    # WannaCry SMB — RAN-007
    if "smb" in pattern or "ms17" in pattern:
        return proto == "TCP" and port in [445, 139]

    # Cobalt Strike — RAN-006
    if "cobaltstrike" in pattern or "cobalt" in pattern:
        return proto == "TCP" and port in [443, 8443, 4444]

    return False


# ── Startup ────────────────────────────────────────────────────
def start_signature_engine():
    """Initialize the engine — load rules and start auto-reloader."""
    count = load_rules_from_db()
    t = threading.Thread(target=_rules_auto_reloader, daemon=True)
    t.start()
    print(f"[SIG ENGINE] Started with {count} rules — auto-reload every 30s")


# ── API helpers ────────────────────────────────────────────────
def get_rule_stats() -> Dict:
    """Return hit counts per rule."""
    return dict(rule_match_counts)


def block_ip_now(ip: str):
    """Block an IP immediately via iptables — called from API."""
    _block_ip_iptables(ip, "MANUAL", "Manual block")


def unblock_ip_now(ip: str):
    """Unblock an IP via iptables — called from API."""
    _unblock_ip_iptables(ip)
