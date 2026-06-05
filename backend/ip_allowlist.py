"""
ip_allowlist.py — Trusted IP / network allowlist
==================================================
Major cloud & CDN providers generate huge volumes of legitimate HTTPS
traffic that DeepDefend sometimes misclassifies as WebAttack. Rather than
block GitHub / Google / Cloudflare, we treat their ranges as trusted.

Used by:
  • correlation_engine — to tag decisions as allowlisted
  • agents (TriageAgent) — to never auto-block a trusted host

This is standard practice in production IDPS (Suricata 'pass' rules,
Snort whitelist, Palo Alto trusted zones).
"""

import ipaddress
from functools import lru_cache

# ─── Trusted CIDR ranges (well-known providers) ───────────────
# Sources: published provider IP ranges (abbreviated to common blocks)
TRUSTED_CIDRS = [
    # Private / local (RFC 1918) — your own LAN
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",          # loopback

    # Google / Google Cloud (common ranges)
    "8.8.8.0/24",
    "8.8.4.0/24",
    "34.0.0.0/8",           # GCP (full /8)
    "35.190.0.0/17",
    "35.184.0.0/13",        # GCP us-central
    "142.250.0.0/15",       # Google services
    "172.217.0.0/16",
    "216.58.192.0/19",
    "74.125.0.0/16",        # Google
    "64.233.160.0/19",      # Google
    "66.102.0.0/20",        # Google
    "72.14.192.0/18",       # Google
    "209.85.128.0/17",      # Google
    "173.194.0.0/16",       # Google

    # Microsoft / Azure (common ranges)
    "13.64.0.0/11",
    "20.0.0.0/8",           # large Azure block
    "40.64.0.0/10",         # Microsoft / Azure (broad)
    "52.96.0.0/12",
    "104.40.0.0/13",
    "13.64.0.0/11",
    "13.104.0.0/14",        # Microsoft
    "131.253.0.0/16",       # Microsoft
    "157.55.0.0/16",        # Microsoft

    # Cloudflare
    "104.16.0.0/13",
    "172.64.0.0/13",
    "131.0.72.0/22",
    "162.158.0.0/15",
    "188.114.96.0/20",

    # GitHub
    "140.82.112.0/20",
    "185.199.108.0/22",
    "143.55.64.0/20",

    # Amazon AWS (common)
    "3.0.0.0/9",
    "18.32.0.0/11",
    "54.144.0.0/12",

    # Meta / Facebook
    "31.13.24.0/21",
    "57.144.0.0/14",
    "157.240.0.0/16",
]

# Specific single IPs to always trust (e.g. your gateway, DNS)
TRUSTED_IPS = {
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
}


# Pre-parse the networks once at import for speed
_NETWORKS = []
for cidr in TRUSTED_CIDRS:
    try:
        _NETWORKS.append(ipaddress.ip_network(cidr, strict=False))
    except ValueError:
        pass


@lru_cache(maxsize=4096)
def is_trusted(ip: str) -> bool:
    """
    Return True if the IP is on the allowlist (trusted, never auto-block).
    Cached for performance — same IP checked thousands of times.
    """
    if not ip:
        return False
    if ip in TRUSTED_IPS:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in _NETWORKS:
        if addr in net:
            return True
    return False


def trust_reason(ip: str) -> str:
    """Human-readable reason an IP is trusted (for logs / UI)."""
    if ip in TRUSTED_IPS:
        return f"{ip} is a trusted public DNS/resolver"
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private:
            return f"{ip} is on the local network (RFC 1918)"
        if addr.is_loopback:
            return f"{ip} is loopback"
    except ValueError:
        return ""
    for net in _NETWORKS:
        try:
            if addr in net:
                return f"{ip} is in trusted range {net}"
        except Exception:
            continue
    return ""


# Quick self-test when run directly
if __name__ == "__main__":
    tests = [
        "192.168.1.106",   # local
        "8.8.8.8",         # google dns
        "140.82.114.21",   # github
        "57.144.149.32",   # meta
        "142.250.202.46",  # google
        "185.220.101.47",  # NOT trusted (Tor exit, real attacker)
        "203.0.113.5",     # NOT trusted (test range)
    ]
    for t in tests:
        print(f"{t:20s} trusted={is_trusted(t)!s:6s} {trust_reason(t)}")
