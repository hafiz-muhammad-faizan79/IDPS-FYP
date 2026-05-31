"""
attack_simulator.py
===================
Generates safe simulated attack traffic to test the IDPS detection chain.

WARNING: Only use on your own network! This sends SYN packets and
mock payloads to your local interface to trigger detection rules.
"""

import time
import random
import threading
from typing import Dict
from scapy.all import IP, TCP, UDP, send, Raw

# Your local IP — discovered at startup
import socket


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


LOCAL_IP = get_local_ip()

# Simulated attacker IPs (these will appear as source in alerts)
ATTACKER_IPS = [
    "185.220.101.47",   # Tor exit node
    "194.165.16.78",
    "103.75.190.12",
    "91.108.4.200",
    "5.188.206.14",
]

# Track simulation state
_simulation_state = {
    "running": False,
    "threads": [],
    "stats":   {"packets_sent": 0, "attacks_run": 0},
}


# ══════════════════════════════════════════════════════════════
# ATTACK GENERATORS
# ══════════════════════════════════════════════════════════════

def syn_flood(target_port: int = 80, count: int = 100):
    """Simulate SYN flood — triggers SIG-003 + DDoS detection."""
    src_ip = "185.220.101.47"  # fixed for demo so correlation can match
    print(f"[ATTACK SIM] SYN flood from {src_ip} → {LOCAL_IP}:{target_port} ({count} pkts)")
    for _ in range(count):
        pkt = IP(src=src_ip, dst=LOCAL_IP) / TCP(
            sport=random.randint(1024, 65535),
            dport=target_port,
            flags="S",
            seq=random.randint(0, 4_000_000_000),
        )
        try:
            send(pkt, verbose=False)
            _simulation_state["stats"]["packets_sent"] += 1
        except Exception as e:
            print(f"[ATTACK SIM] Send error: {e}")
            return
        time.sleep(0.01)
    _simulation_state["stats"]["attacks_run"] += 1


def port_scan(start_port: int = 20, end_port: int = 1024):
    """Simulate Nmap-style port scan — triggers SIG-006."""
    src_ip = "185.220.101.47"  # fixed for demo so correlation can match
    print(f"[ATTACK SIM] Port scan from {src_ip} → {LOCAL_IP}:{start_port}-{end_port}")
    for port in range(start_port, min(end_port, start_port + 50)):
        pkt = IP(src=src_ip, dst=LOCAL_IP) / TCP(
            sport=random.randint(1024, 65535),
            dport=port,
            flags="S",
        )
        try:
            send(pkt, verbose=False)
            _simulation_state["stats"]["packets_sent"] += 1
        except Exception:
            return
        time.sleep(0.02)
    _simulation_state["stats"]["attacks_run"] += 1


def ssh_brute_force(count: int = 30):
    """Simulate SSH brute force — triggers SIG-004."""
    src_ip = "185.220.101.47"  # fixed for demo so correlation can match
    print(f"[ATTACK SIM] SSH brute force from {src_ip} → {LOCAL_IP}:22 ({count} attempts)")
    for _ in range(count):
        pkt = IP(src=src_ip, dst=LOCAL_IP) / TCP(
            sport=random.randint(1024, 65535),
            dport=22,
            flags="S",
        )
        try:
            send(pkt, verbose=False)
            _simulation_state["stats"]["packets_sent"] += 1
        except Exception:
            return
        time.sleep(0.05)
    _simulation_state["stats"]["attacks_run"] += 1


def sql_injection_attempt():
    """Simulate SQL injection HTTP payload — triggers SIG-001."""
    src_ip  = random.choice(ATTACKER_IPS)
    payload = (
        b"GET /login?user=admin' UNION SELECT * FROM users-- HTTP/1.1\r\n"
        b"Host: " + LOCAL_IP.encode() + b"\r\n"
        b"User-Agent: AttackBot/1.0\r\n\r\n"
    )
    print(f"[ATTACK SIM] SQL injection from {src_ip} → {LOCAL_IP}:80")
    pkt = IP(src=src_ip, dst=LOCAL_IP) / TCP(
        sport=random.randint(1024, 65535),
        dport=80,
        flags="PA",
    ) / Raw(load=payload)
    try:
        send(pkt, verbose=False)
        _simulation_state["stats"]["packets_sent"] += 1
        _simulation_state["stats"]["attacks_run"] += 1
    except Exception as e:
        print(f"[ATTACK SIM] Send error: {e}")


def rdp_brute_force(count: int = 20):
    """Simulate RDP brute force — triggers SIG-010."""
    src_ip = "185.220.101.47"  # fixed for demo so correlation can match
    print(f"[ATTACK SIM] RDP brute force from {src_ip} → {LOCAL_IP}:3389")
    for _ in range(count):
        pkt = IP(src=src_ip, dst=LOCAL_IP) / TCP(
            sport=random.randint(1024, 65535),
            dport=3389,
            flags="S",
        )
        try:
            send(pkt, verbose=False)
            _simulation_state["stats"]["packets_sent"] += 1
        except Exception:
            return
        time.sleep(0.05)
    _simulation_state["stats"]["attacks_run"] += 1


# ══════════════════════════════════════════════════════════════
# ORCHESTRATION
# ══════════════════════════════════════════════════════════════

def run_all_attacks():
    """Run all attack types in sequence — full demo."""
    _simulation_state["running"] = True
    print(f"\n{'='*60}")
    print(f"[ATTACK SIM] STARTING FULL DEMO — target {LOCAL_IP}")
    print(f"{'='*60}\n")

    syn_flood(target_port=80, count=50)
    time.sleep(2)

    port_scan(start_port=20, end_port=70)
    time.sleep(2)

    ssh_brute_force(count=20)
    time.sleep(2)

    sql_injection_attempt()
    time.sleep(2)

    rdp_brute_force(count=15)

    print(f"\n{'='*60}")
    print(f"[ATTACK SIM] DEMO COMPLETE")
    print(f"  Packets sent: {_simulation_state['stats']['packets_sent']}")
    print(f"  Attacks run:  {_simulation_state['stats']['attacks_run']}")
    print(f"{'='*60}\n")
    _simulation_state["running"] = False


def run_async(attack_type: str = "all"):
    """Launch attack in background thread."""
    attack_map = {
        "all":        run_all_attacks,
        "syn_flood":  lambda: syn_flood(80, 50),
        "port_scan":  lambda: port_scan(20, 70),
        "ssh_brute":  lambda: ssh_brute_force(20),
        "sql_inject": sql_injection_attempt,
        "rdp_brute":  lambda: rdp_brute_force(15),
    }
    target = attack_map.get(attack_type, run_all_attacks)
    t = threading.Thread(target=target, daemon=True)
    t.start()
    _simulation_state["threads"].append(t)
    return {"started": True, "attack": attack_type}


def get_status():
    return {
        "running":      _simulation_state["running"],
        "stats":        dict(_simulation_state["stats"]),
        "local_ip":     LOCAL_IP,
        "attacker_ips": ATTACKER_IPS,
    }


# ══════════════════════════════════════════════════════════════
# Run from command line
# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import sys
    attack = sys.argv[1] if len(sys.argv) > 1 else "all"
    print(f"[ATTACK SIM] Local IP: {LOCAL_IP}")
    print(f"[ATTACK SIM] Running attack: {attack}")
    if attack == "all":
        run_all_attacks()
    else:
        result = run_async(attack)
        print(result)
        time.sleep(10)  # wait for completion
