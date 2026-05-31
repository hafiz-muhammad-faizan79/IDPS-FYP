"""
correlation_engine.py
=====================
ThreatCorrelationEngine — combines ShieldNet (signatures) + DeepDefend (AI)
results into a single high-confidence threat decision.
"""

import threading
import time
from collections import deque, defaultdict
from datetime import datetime
from typing import Dict, List, Optional


AI_CONFIDENCE_THRESHOLD = 70.0
CORRELATION_WINDOW      = 15.0

SEVERITY_RANK    = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
RANK_TO_SEVERITY = {v: k for k, v in SEVERITY_RANK.items()}


class CorrelationState:
    def __init__(self):
        self.lock = threading.Lock()
        self.shieldnet_events: Dict[str, List[Dict]] = defaultdict(list)
        self.deepdefend_events: Dict[str, List[Dict]] = defaultdict(list)
        self.correlations: deque = deque(maxlen=200)
        self.ip_reputation: Dict[str, str] = {}
        self.stats = {
            "total_correlations":  0,
            "both_engines_match":  0,
            "shieldnet_only":      0,
            "deepdefend_only":     0,
            "false_positives_filtered": 0,
        }

    def cleanup_old_events(self):
        cutoff = time.time() - CORRELATION_WINDOW
        with self.lock:
            for ip in list(self.shieldnet_events.keys()):
                self.shieldnet_events[ip] = [e for e in self.shieldnet_events[ip] if e["time"] > cutoff]
                if not self.shieldnet_events[ip]:
                    del self.shieldnet_events[ip]
            for ip in list(self.deepdefend_events.keys()):
                self.deepdefend_events[ip] = [e for e in self.deepdefend_events[ip] if e["time"] > cutoff]
                if not self.deepdefend_events[ip]:
                    del self.deepdefend_events[ip]


state = CorrelationState()


def _refresh_ip_reputation():
    try:
        from database import SessionLocal
        from models.configuration import BlockedIP
        db = SessionLocal()
        blocked = db.query(BlockedIP).all()
        with state.lock:
            state.ip_reputation = {b.ip: "blocked" for b in blocked}
        db.close()
    except Exception as e:
        print(f"[CORRELATION] IP reputation refresh failed: {e}")


def _ip_reputation_refresher():
    while True:
        _refresh_ip_reputation()
        time.sleep(60)


def _correlate(src_ip: str) -> Optional[Dict]:
    with state.lock:
        sn_events    = list(state.shieldnet_events.get(src_ip, []))
        dd_events    = list(state.deepdefend_events.get(src_ip, []))
        is_known_bad = state.ip_reputation.get(src_ip) == "blocked"

    if not sn_events and not dd_events:
        return None

    has_shieldnet = len(sn_events) > 0
    dd_threats = [e for e in dd_events
                  if e["class"] != "BENIGN" and e["confidence"] >= AI_CONFIDENCE_THRESHOLD]

    if not has_shieldnet and not dd_threats:
        return None

    decision = {
        "src_ip":             src_ip,
        "shieldnet_matches":  len(sn_events),
        "deepdefend_matches": len(dd_threats),
        "is_known_bad":       is_known_bad,
        "timestamp":          datetime.now().isoformat(),
        "engines": {
            "shieldnet":  [e["rule_id"] for e in sn_events],
            "deepdefend": [{"class": e["class"], "conf": e["confidence"]} for e in dd_threats],
        },
    }

    if has_shieldnet and dd_threats:
        sn_max_sev = max(SEVERITY_RANK.get(e["severity"], 0) for e in sn_events)
        dd_max_sev = max(SEVERITY_RANK.get(e["severity"], 0) for e in dd_threats)
        final_rank = min(max(sn_max_sev, dd_max_sev) + 1, 4)
        decision["severity"]    = RANK_TO_SEVERITY[final_rank]
        decision["confidence"]  = 95.0
        decision["category"]    = "CONFIRMED THREAT"
        decision["recommended"] = "BLOCK"
        decision["reason"]      = f"Both engines confirmed threat from {src_ip}"
        state.stats["both_engines_match"] += 1

    elif has_shieldnet:
        sn_max_sev = max(SEVERITY_RANK.get(e["severity"], 0) for e in sn_events)
        decision["severity"]    = RANK_TO_SEVERITY[sn_max_sev]
        decision["confidence"]  = 85.0
        decision["category"]    = "SIGNATURE MATCH"
        decision["recommended"] = "BLOCK" if sn_max_sev >= 3 else "ALERT"
        decision["reason"]      = f"ShieldNet rule(s) matched: {[e['rule_id'] for e in sn_events]}"
        state.stats["shieldnet_only"] += 1

    elif dd_threats:
        avg_conf = sum(e["confidence"] for e in dd_threats) / len(dd_threats)
        if avg_conf < 80:
            state.stats["false_positives_filtered"] += 1
            return None
        dd_max_sev = max(SEVERITY_RANK.get(e["severity"], 0) for e in dd_threats)
        decision["severity"]    = RANK_TO_SEVERITY[dd_max_sev]
        decision["confidence"]  = avg_conf
        decision["category"]    = "AI ANOMALY"
        decision["recommended"] = "ALERT"
        decision["reason"]      = f"DeepDefend detected {dd_threats[0]['class']} ({avg_conf:.1f}%)"
        state.stats["deepdefend_only"] += 1

    else:
        return None

    if is_known_bad:
        cur_rank = SEVERITY_RANK[decision["severity"]]
        decision["severity"]    = RANK_TO_SEVERITY[min(cur_rank + 1, 4)]
        decision["recommended"] = "BLOCK"
        decision["reason"]     += " (IP previously blocked)"

    state.stats["total_correlations"] += 1
    return decision


def report_shieldnet_match(src_ip: str, rule_id: str, rule_name: str,
                            severity: str, action: str):
    event = {
        "time":      time.time(),
        "rule_id":   rule_id,
        "rule_name": rule_name,
        "severity":  severity,
        "action":    action,
    }
    with state.lock:
        state.shieldnet_events[src_ip].append(event)
    decision = _correlate(src_ip)
    if decision:
        _process_decision(decision)


def report_deepdefend_prediction(src_ip: str, threat_class: str,
                                  confidence: float, severity: str):
    if threat_class == "BENIGN":
        return
    event = {
        "time":       time.time(),
        "class":      threat_class,
        "confidence": confidence,
        "severity":   severity,
    }
    with state.lock:
        state.deepdefend_events[src_ip].append(event)
    decision = _correlate(src_ip)
    if decision:
        _process_decision(decision)


def _process_decision(decision: Dict):
    state.correlations.appendleft(decision)

    try:
        from database import SessionLocal
        from models.network import NetworkAlert, NetworkLog
        db = SessionLocal()
        alert = NetworkAlert(
            severity = decision["severity"],
            src_ip   = decision["src_ip"],
            dst_ip   = "multiple",
            message  = f"[CORRELATION] {decision['category']} - {decision['reason']}",
            protocol = "MULTI",
            port     = 0,
        )
        db.add(alert)
        log = NetworkLog(
            status  = decision["recommended"],
            src_ip  = decision["src_ip"],
            event   = "CORRELATION",
            result  = "WARNING" if decision["severity"] in ("High","Critical") else "INFO",
            message = f"[{decision['category']}] {decision['reason']} | conf={decision['confidence']:.1f}%",
        )
        db.add(log)
        db.commit()
        db.close()
    except Exception as e:
        print(f"[CORRELATION] DB log error: {e}")

    if decision["recommended"] == "BLOCK" and decision["confidence"] >= 90:
        try:
            from signature_engine import block_ip_now
            block_ip_now(decision["src_ip"])
        except Exception as e:
            print(f"[CORRELATION] Auto-block error: {e}")


def get_correlations(limit: int = 20) -> List[Dict]:
    return list(state.correlations)[:limit]


def get_correlation_stats() -> Dict:
    with state.lock:
        return {
            "total_correlations":     state.stats["total_correlations"],
            "both_engines_match":     state.stats["both_engines_match"],
            "shieldnet_only":         state.stats["shieldnet_only"],
            "deepdefend_only":        state.stats["deepdefend_only"],
            "false_positives_filtered": state.stats["false_positives_filtered"],
            "active_shieldnet_ips":   len(state.shieldnet_events),
            "active_deepdefend_ips":  len(state.deepdefend_events),
            "blocked_ip_count":       len(state.ip_reputation),
        }


def _cleanup_worker():
    while True:
        time.sleep(5)
        state.cleanup_old_events()


def start_correlation_engine():
    threading.Thread(target=_cleanup_worker,           daemon=True).start()
    threading.Thread(target=_ip_reputation_refresher,  daemon=True).start()
    _refresh_ip_reputation()
    print("[CORRELATION] ✅ ThreatCorrelationEngine started")
