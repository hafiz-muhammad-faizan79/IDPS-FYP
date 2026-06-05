"""
base.py — Foundation for all CyGuardian-X agents
=================================================
Provides:
  • BaseAgent class with lifecycle (start, stop, heartbeat, run-loop)
  • Event bus helpers (publish_event, consume_events)
  • Action helpers (recommend_action, mark_executed)
  • Common logging + state management
"""

import json
import threading
import time
import traceback
from datetime import datetime
from typing import Optional, List, Dict, Any

from database import SessionLocal
from models.agent import AgentEvent, AgentAction


# ══════════════════════════════════════════════════════════════
# BASE AGENT
# ══════════════════════════════════════════════════════════════
class BaseAgent:
    """All CyGuardian-X agents inherit from this.

    Subclasses must implement:
      • agent_name (class attr)
      • subscribes_to (class attr, list of event types)
      • handle_event(event) — processes one event at a time

    Optional:
      • tick() — called once per poll interval if no events are pending
    """

    agent_name: str        = "BASE"
    subscribes_to: List[str] = []          # which event types this agent processes
    poll_interval: float   = 2.0           # seconds between event-bus polls

    def __init__(self):
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._heartbeat_at: Optional[datetime] = None
        self.events_processed = 0
        self.actions_recommended = 0
        self.errors = 0

    # ─── Lifecycle ────────────────────────────────────────────
    def start(self):
        if self._thread and self._thread.is_alive():
            self.log("already running")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name=self.agent_name, daemon=True)
        self._thread.start()
        self.log("✅ started")

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self.log("⏹ stopped")

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ─── Main loop ────────────────────────────────────────────
    def _run(self):
        self.log(f"main loop starting (subscribes to: {self.subscribes_to or 'tick-only'})")
        while not self._stop_event.is_set():
            try:
                self._heartbeat_at = datetime.utcnow()

                # Process pending events
                events = self.consume_events(limit=10)
                if events:
                    for evt in events:
                        try:
                            self.handle_event(evt)
                            self.events_processed += 1
                        except Exception as e:
                            self.errors += 1
                            self.log(f"⚠ handle_event error: {e}")
                            traceback.print_exc()
                else:
                    # No events → call tick() if implemented
                    self.tick()

                # Sleep with early-exit on stop
                self._stop_event.wait(self.poll_interval)

            except Exception as e:
                self.errors += 1
                self.log(f"⚠ run-loop error: {e}")
                self._stop_event.wait(self.poll_interval)

    # ─── Subclass hooks ───────────────────────────────────────
    def handle_event(self, event: Dict[str, Any]):
        """Process a single event. Override in subclasses."""
        pass

    def tick(self):
        """Optional periodic work when no events. Override if needed."""
        pass

    # ─── Event bus operations ─────────────────────────────────
    def consume_events(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Fetch unprocessed events matching this agent's subscriptions."""
        if not self.subscribes_to:
            return []
        db = SessionLocal()
        try:
            rows = db.query(AgentEvent).filter(
                AgentEvent.event_type.in_(self.subscribes_to)
            ).order_by(AgentEvent.created_at.desc()).limit(limit).all()

            results = []
            for r in rows:
                processed = json.loads(r.processed_by or "[]")
                if self.agent_name in processed:
                    continue
                results.append({
                    "id":           r.id,
                    "event_type":   r.event_type,
                    "source_agent": r.source_agent,
                    "src_ip":       r.src_ip,
                    "severity":     r.severity,
                    "category":     r.category,
                    "payload":      json.loads(r.payload) if r.payload else {},
                    "created_at":   r.created_at.isoformat() if r.created_at else None,
                })
                # Mark as processed by this agent
                processed.append(self.agent_name)
                r.processed_by = json.dumps(processed)
            db.commit()
            return results
        except Exception as e:
            self.log(f"⚠ consume_events error: {e}")
            db.rollback()
            return []
        finally:
            db.close()

    def publish_event(self, event_type: str, payload: Dict[str, Any],
                      src_ip: Optional[str] = None,
                      severity: Optional[str] = None,
                      category: Optional[str] = None):
        """Publish an event to the bus for other agents."""
        db = SessionLocal()
        try:
            evt = AgentEvent(
                event_type   = event_type,
                source_agent = self.agent_name,
                src_ip       = src_ip,
                severity     = severity,
                category     = category,
                payload      = json.dumps(payload, default=str),
                processed_by = "[]",
            )
            db.add(evt)
            db.commit()
        except Exception as e:
            self.log(f"⚠ publish_event error: {e}")
            db.rollback()
        finally:
            db.close()

    # ─── Action recommendations ───────────────────────────────
    def recommend_action(self, action_type: str, target: str,
                         severity: str, confidence: int,
                         autonomy_level: str, reasoning: str = "",
                         raw_decision: Optional[Dict] = None) -> Optional[int]:
        """
        Submit a recommended action. Returns the new AgentAction id.
        autonomy_level: AUTO | APPROVAL_REQUIRED | RECOMMEND_ONLY
        """
        db = SessionLocal()
        try:
            action = AgentAction(
                agent_name     = self.agent_name,
                action_type    = action_type,
                target         = target,
                severity       = severity,
                confidence     = confidence,
                autonomy_level = autonomy_level,
                status         = "AUTO_APPROVED" if autonomy_level == "AUTO" else "PENDING",
                reasoning      = reasoning,
                raw_decision   = json.dumps(raw_decision, default=str) if raw_decision else None,
            )
            db.add(action)
            db.commit()
            db.refresh(action)
            self.actions_recommended += 1
            return action.id
        except Exception as e:
            self.log(f"⚠ recommend_action error: {e}")
            db.rollback()
            return None
        finally:
            db.close()

    def mark_executed(self, action_id: int, success: bool, error: str = ""):
        """Mark an AgentAction as EXECUTED or FAILED."""
        db = SessionLocal()
        try:
            action = db.query(AgentAction).filter(AgentAction.id == action_id).first()
            if action:
                action.status = "EXECUTED" if success else "FAILED"
                action.executed_at = datetime.utcnow()
                if error:
                    action.error_message = error
                db.commit()
        except Exception as e:
            self.log(f"⚠ mark_executed error: {e}")
            db.rollback()
        finally:
            db.close()

    # ─── Logging ──────────────────────────────────────────────
    def log(self, message: str):
        print(f"[AGENT:{self.agent_name}] {message}")

    # ─── Status snapshot ──────────────────────────────────────
    def status(self) -> Dict[str, Any]:
        return {
            "name":                self.agent_name,
            "running":             self.is_running(),
            "subscribes_to":       self.subscribes_to,
            "last_heartbeat":      self._heartbeat_at.isoformat() if self._heartbeat_at else None,
            "events_processed":    self.events_processed,
            "actions_recommended": self.actions_recommended,
            "errors":              self.errors,
        }
