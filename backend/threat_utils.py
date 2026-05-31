"""
threat_utils.py
===============
Shared utilities for ShieldNet and DeepDefend engines.
Single source of truth for identifying the "attacker" side of a flow.
"""

import ipaddress


def is_local_ip(ip: str) -> bool:
    """RFC 1918 + loopback + link-local."""
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except Exception:
        return False


def pick_attacker_ip(src: str, dst: str) -> str:
    """
    Identify the attacker IP from a packet/flow.
    Priority:
      1. If one side is local and other is external, external is attacker.
      2. If both external, use src (best guess).
      3. If both local, use src.
    """
    src_local = is_local_ip(src)
    dst_local = is_local_ip(dst)
    if src_local and not dst_local:
        return dst   # external is attacker
    if dst_local and not src_local:
        return src   # external is attacker
    return src       # both local or both external
