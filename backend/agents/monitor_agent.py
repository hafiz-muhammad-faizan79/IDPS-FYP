"""
monitor_agent.py — The "eyes" of the agent system.
====================================================
Periodically polls the in-memory correlation log (no event bus consumer yet —
correlations are pushed via report_correlation in correlation_engine.py).

The MonitorAgent's job:
  1. Detect new correlations since last tick
  2. Enrich with IP reputation, ASN, geo (basic for now)
  3. Publish a THREAT_DETECTED event for downstream agents
"""

import time
from agents.base import BaseAgent
from threat_utils import is_local_ip


class MonitorAgent(BaseAgent):
    agent_name    = "MONITOR"
    subscribes_to = []           # tick-only agent (no bus consumption)
    poll_interval = 3.0          # check every 3 seconds

    def __init__(self):
        super().__init__()
        self._seen_correlation_ids = set()
        self._max_seen = 500     # bounded memory

    def tick(self):
        """Poll the correlation engine for new decisions."""
        try:
            from correlation_engine import get_correlations
        except Exception as e:
            self.log(f"correlator not available yet: {e}")
            return

        recent = get_correlations(limit=20)
        new_count = 0

        for corr in recent:
            # Build a stable ID for de-duplication
            corr_id = (corr.get("src_ip"), corr.get("timestamp"))
            if corr_id in self._seen_correlation_ids:
                continue
            self._seen_correlation_ids.add(corr_id)
            new_count += 1

            # Enrich with basic context
            src_ip       = corr.get("src_ip", "unknown")
            enrichment = {
                "is_local":      is_local_ip(src_ip),
                "engines_fired": corr.get("shieldnet_matches", 0) + corr.get("deepdefend_matches", 0),
                "both_engines":  (corr.get("shieldnet_matches", 0) > 0 and corr.get("deepdefend_matches", 0) > 0),
            }

            # Publish to event bus
            self.publish_event(
                event_type = "THREAT_DETECTED",
                src_ip     = src_ip,
                severity   = corr.get("severity"),
                category   = corr.get("category"),
                payload    = {
                    "correlation": corr,
                    "enrichment":  enrichment,
                },
            )

        # Bound memory
        if len(self._seen_correlation_ids) > self._max_seen:
            # Keep last 250
            self._seen_correlation_ids = set(list(self._seen_correlation_ids)[-250:])

        if new_count > 0:
            self.log(f"observed {new_count} new threats → published")
