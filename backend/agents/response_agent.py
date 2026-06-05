"""
response_agent.py — Executes approved actions.
================================================
Listens for TRIAGE_COMPLETE events.
  • If autonomy=AUTO          → executes immediately
  • If autonomy=APPROVAL_REQUIRED → waits in queue for admin approval
  • If autonomy=RECOMMEND_ONLY → logs only, no execution

Current supported actions:
  • BLOCK_IP    → iptables DROP via signature_engine.block_ip_now()
  • MONITOR     → no-op (just records to audit trail)
  • ALERT       → already handled by NotificationService
"""

from agents.base import BaseAgent


class ResponseAgent(BaseAgent):
    agent_name    = "RESPONSE"
    subscribes_to = ["TRIAGE_COMPLETE"]
    poll_interval = 2.0

    def handle_event(self, event):
        payload     = event["payload"]
        action_id   = payload.get("action_id")
        action_type = payload.get("action_type")
        autonomy    = payload.get("autonomy")
        src_ip      = event["src_ip"]

        if not action_id:
            self.log(f"⚠ no action_id in event, skipping")
            return

        # Only execute AUTO actions immediately
        if autonomy != "AUTO":
            self.log(f"{action_type} for {src_ip} requires {autonomy} — skipping execution")
            return

        # Execute the action
        success = False
        error_msg = ""

        try:
            if action_type == "BLOCK_IP":
                success = self._block_ip(src_ip)
                if not success:
                    error_msg = "block_ip_now() returned False"
            elif action_type == "MONITOR":
                # Just a no-op record
                success = True
            elif action_type == "ALERT":
                # Already dispatched by NotificationService
                success = True
            else:
                error_msg = f"unknown action_type: {action_type}"

        except Exception as e:
            error_msg = str(e)

        # Mark the AgentAction row as EXECUTED or FAILED
        self.mark_executed(action_id, success, error_msg)

        # Publish ACTION_EXECUTED event for AuditAgent / NotifyAgent later
        self.publish_event(
            event_type = "ACTION_EXECUTED",
            src_ip     = src_ip,
            severity   = event.get("severity"),
            category   = event.get("category"),
            payload    = {
                "action_id":   action_id,
                "action_type": action_type,
                "success":     success,
                "error":       error_msg,
            },
        )

        if success:
            self.log(f"✅ EXECUTED {action_type} on {src_ip}")
        else:
            self.log(f"❌ FAILED {action_type} on {src_ip}: {error_msg}")

    def _block_ip(self, src_ip: str) -> bool:
        """Wrap signature_engine.block_ip_now() with error handling."""
        try:
            from signature_engine import block_ip_now
            block_ip_now(src_ip)
            return True
        except Exception as e:
            self.log(f"⚠ block_ip failed: {e}")
            return False
