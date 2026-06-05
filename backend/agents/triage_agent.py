"""
triage_agent.py — Threat scoring & decision-making.
=====================================================
Listens for THREAT_DETECTED events from MonitorAgent and decides:
  • AUTO ........... high-confidence threat → recommend immediate action
  • APPROVAL_REQUIRED  medium-confidence → recommend, wait for human
  • RECOMMEND_ONLY ... low-confidence → log, no action

Decision matrix (BALANCED autonomy):
  ┌─────────────────────────────┬───────────────────┐
  │ Condition                   │ Autonomy          │
  ├─────────────────────────────┼───────────────────┤
  │ Both engines + conf ≥ 90    │ AUTO              │
  │ Critical severity + conf≥85 │ AUTO              │
  │ High severity + conf ≥ 80   │ APPROVAL_REQUIRED │
  │ Anything else               │ RECOMMEND_ONLY    │
  └─────────────────────────────┴───────────────────┘
"""

from agents.base import BaseAgent
from ip_allowlist import is_trusted, trust_reason


class TriageAgent(BaseAgent):
    agent_name    = "TRIAGE"
    subscribes_to = ["THREAT_DETECTED"]
    poll_interval = 2.0

    def handle_event(self, event):
        payload = event["payload"]
        corr        = payload.get("correlation", {})
        enrichment  = payload.get("enrichment", {})

        src_ip     = event["src_ip"] or "unknown"
        severity   = event["severity"] or "Info"
        confidence = corr.get("confidence", 0)
        category   = event["category"] or "UNKNOWN"
        both       = enrichment.get("both_engines", False)
        is_local   = enrichment.get("is_local", False)

        # Engine breakdown for corroboration logic
        sn_matches  = corr.get("shieldnet_matches", 0)
        dd_matches  = corr.get("deepdefend_matches", 0)
        engines     = corr.get("engines", {})
        ai_classes  = [d.get("class", "") for d in engines.get("deepdefend", [])]
        # WebAttack is DeepDefend's weakest class (high false-positive rate on normal HTTPS)
        ai_only_webattack = (
            sn_matches == 0
            and dd_matches > 0
            and len(ai_classes) > 0
            and all(c == "WebAttack" for c in ai_classes)
        )

        # ─── Decision matrix ──────────────────────────────────
        autonomy   = "RECOMMEND_ONLY"
        action     = "ALERT"

        if both and confidence >= 90:
            autonomy = "AUTO"
            action   = "BLOCK_IP"
        elif severity == "Critical" and confidence >= 85:
            autonomy = "AUTO"
            action   = "BLOCK_IP"
        elif severity == "High" and confidence >= 80:
            autonomy = "APPROVAL_REQUIRED"
            action   = "BLOCK_IP"
        elif severity in ("Medium", "Low"):
            autonomy = "RECOMMEND_ONLY"
            action   = "MONITOR"
        else:
            autonomy = "RECOMMEND_ONLY"
            action   = "MONITOR"

        # Trusted allowlist guard — never block known-good providers (Google, GitHub, etc.)
        if is_trusted(src_ip):
            autonomy = "RECOMMEND_ONLY"
            action   = "MONITOR"
            self.log(f"✓ {src_ip} is ALLOWLISTED — {trust_reason(src_ip)} → MONITOR only")

        # Don't ever auto-act on local IPs (false-positive guard)
        elif is_local and autonomy == "AUTO":
            autonomy = "APPROVAL_REQUIRED"
            self.log(f"⚠ downgraded {src_ip} (local IP) from AUTO → APPROVAL_REQUIRED")

        # DEBUG: log the corroboration inputs

        # ROOT-CAUSE GUARD: AI-only WebAttack detections are low-trust.
        # DeepDefend frequently misclassifies normal HTTPS as WebAttack.
        # Require a ShieldNet signature to corroborate before any BLOCK.
        if ai_only_webattack and action == "BLOCK_IP" and not is_trusted(src_ip):
            autonomy = "RECOMMEND_ONLY"
            action   = "MONITOR"
            self.log(f"⚠ {src_ip}: AI-only WebAttack (no signature) — downgraded to MONITOR (corroboration required)")

        # ─── Build reasoning string ───────────────────────────
        reasoning_parts = [
            f"Severity={severity}, Confidence={confidence:.0f}%, Category={category}",
            f"Engines fired: ShieldNet={corr.get('shieldnet_matches',0)}, DeepDefend={corr.get('deepdefend_matches',0)}",
        ]
        if both:           reasoning_parts.append("Both engines corroborate (high signal)")
        if is_local:       reasoning_parts.append("Source IP is LOCAL — extra caution required")
        if corr.get("is_known_bad"): reasoning_parts.append("IP appears on known-bad reputation list")
        reasoning_parts.append(f"Decision: {action} via {autonomy} autonomy")
        reasoning = " | ".join(reasoning_parts)

        # ─── Recommend the action ─────────────────────────────
        action_id = self.recommend_action(
            action_type    = action,
            target         = src_ip,
            severity       = severity,
            confidence     = int(confidence),
            autonomy_level = autonomy,
            reasoning      = reasoning,
            raw_decision   = corr,
        )

        # ─── Publish TRIAGE_COMPLETE for downstream agents ────
        self.publish_event(
            event_type = "TRIAGE_COMPLETE",
            src_ip     = src_ip,
            severity   = severity,
            category   = category,
            payload    = {
                "action_id":     action_id,
                "action_type":   action,
                "autonomy":      autonomy,
                "confidence":    confidence,
                "reasoning":     reasoning,
                "original":      corr,
            },
        )

        self.log(f"triaged {src_ip} → {action} ({autonomy}, {confidence:.0f}%)")
