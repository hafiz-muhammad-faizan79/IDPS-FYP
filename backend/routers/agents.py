"""
agents.py — API endpoints for the multi-agent system
======================================================
Exposes:
  GET    /api/agents/status                    Live status of every agent
  GET    /api/agents/actions                   Recent actions (any status)
  GET    /api/agents/actions/pending           Actions awaiting human approval
  GET    /api/agents/events                    Recent events on the bus
  POST   /api/agents/actions/{id}/approve      Admin approves → executes
  POST   /api/agents/actions/{id}/reject       Admin rejects → marks REJECTED
"""

import json
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc

from database import get_db
from auth import get_current_user, require_role
from models.user import User
from models.agent import AgentEvent, AgentAction

router = APIRouter(prefix="/api/agents", tags=["Agents"])


# ══════════════════════════════════════════════════════════════
# STATUS
# ══════════════════════════════════════════════════════════════
@router.get("/status")
def agent_status(user: User = Depends(get_current_user)):
    """Live snapshot of every running agent."""
    from agents.manager import get_all_status
    return {"agents": get_all_status()}


# ══════════════════════════════════════════════════════════════
# ACTIONS LISTING
# ══════════════════════════════════════════════════════════════
@router.get("/actions")
def list_actions(
    status: Optional[str] = None,
    limit:  int = 50,
    db:     Session = Depends(get_db),
    user:   User   = Depends(get_current_user),
):
    """List recent actions. Filter by status (PENDING|APPROVED|REJECTED|EXECUTED|FAILED|AUTO_APPROVED)."""
    q = db.query(AgentAction)
    if status:
        q = q.filter(AgentAction.status == status.upper())
    rows = q.order_by(desc(AgentAction.created_at)).limit(limit).all()
    return {
        "actions": [_serialize_action(a) for a in rows],
        "count":   len(rows),
    }


@router.get("/actions/pending")
def list_pending(
    limit: int = 50,
    db:    Session = Depends(get_db),
    user:  User   = Depends(get_current_user),
):
    """Actions awaiting human approval."""
    rows = db.query(AgentAction).filter(
        AgentAction.status == "PENDING",
        AgentAction.autonomy_level == "APPROVAL_REQUIRED",
    ).order_by(desc(AgentAction.created_at)).limit(limit).all()
    return {
        "actions": [_serialize_action(a) for a in rows],
        "count":   len(rows),
    }


# ══════════════════════════════════════════════════════════════
# EVENT BUS
# ══════════════════════════════════════════════════════════════
@router.get("/events")
def list_events(
    limit: int = 50,
    db:    Session = Depends(get_db),
    user:  User   = Depends(get_current_user),
):
    rows = db.query(AgentEvent).order_by(desc(AgentEvent.created_at)).limit(limit).all()
    return {
        "events": [{
            "id":           e.id,
            "event_type":   e.event_type,
            "source_agent": e.source_agent,
            "src_ip":       e.src_ip,
            "severity":     e.severity,
            "category":     e.category,
            "payload":      json.loads(e.payload) if e.payload else {},
            "processed_by": json.loads(e.processed_by) if e.processed_by else [],
            "created_at":   e.created_at.isoformat() if e.created_at else None,
        } for e in rows],
        "count": len(rows),
    }


# ══════════════════════════════════════════════════════════════
# APPROVE / REJECT
# ══════════════════════════════════════════════════════════════
@router.post("/actions/{action_id}/approve")
def approve_action(
    action_id: int,
    db:        Session = Depends(get_db),
    user:      User    = Depends(require_role("admin", "soc_lead")),
):
    """Admin approves a pending action → executes it."""
    action = db.query(AgentAction).filter(AgentAction.id == action_id).first()
    if not action:
        raise HTTPException(404, "Action not found")
    if action.status != "PENDING":
        raise HTTPException(400, f"Action is {action.status}, not PENDING")

    # Mark approved
    action.status      = "APPROVED"
    action.approved_by = user.username
    action.approved_at = datetime.utcnow()
    db.commit()

    # Execute it
    success, err = _execute_action(action)

    action.status        = "EXECUTED" if success else "FAILED"
    action.executed_at   = datetime.utcnow()
    action.error_message = err if not success else None
    db.commit()

    return {
        "ok":       True,
        "executed": success,
        "error":    err,
        "action":   _serialize_action(action),
    }


@router.post("/actions/{action_id}/reject")
def reject_action(
    action_id: int,
    db:        Session = Depends(get_db),
    user:      User    = Depends(require_role("admin", "soc_lead")),
):
    """Admin rejects a pending action."""
    action = db.query(AgentAction).filter(AgentAction.id == action_id).first()
    if not action:
        raise HTTPException(404, "Action not found")
    if action.status != "PENDING":
        raise HTTPException(400, f"Action is {action.status}, not PENDING")

    action.status      = "REJECTED"
    action.approved_by = user.username
    action.approved_at = datetime.utcnow()
    db.commit()

    return {"ok": True, "action": _serialize_action(action)}


# ══════════════════════════════════════════════════════════════
# LLM REASONING (on-demand)
# ══════════════════════════════════════════════════════════════
@router.post("/actions/{action_id}/explain")
def explain_action(
    action_id: int,
    db:        Session = Depends(get_db),
    user:      User    = Depends(get_current_user),
):
    """Generate (or regenerate) an LLM explanation for an action on-demand."""
    import json as _json
    from agent_reasoning import generate_reasoning

    action = db.query(AgentAction).filter(AgentAction.id == action_id).first()
    if not action:
        raise HTTPException(404, "Action not found")

    action_dict = _serialize_action(action)
    correlation = None
    if action.raw_decision:
        try:
            correlation = _json.loads(action.raw_decision)
        except Exception:
            correlation = None

    result = generate_reasoning(action_dict, correlation)

    # Persist the LLM reasoning back to the action (overwrites template)
    if result["source"] == "llm":
        action.reasoning = result["reasoning"]
        db.commit()

    return {
        "action_id": action_id,
        "reasoning": result["reasoning"],
        "source":    result["source"],
        "error":     result["error"],
    }


@router.get("/reasoning/health")
def reasoning_health(user: User = Depends(get_current_user)):
    """Check if the local LLM (Ollama) is available."""
    from agent_reasoning import health_check
    return health_check()


# ══════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════
def _serialize_action(a: AgentAction) -> dict:
    return {
        "id":             a.id,
        "agent_name":     a.agent_name,
        "action_type":    a.action_type,
        "target":         a.target,
        "severity":       a.severity,
        "confidence":     a.confidence,
        "autonomy_level": a.autonomy_level,
        "status":         a.status,
        "reasoning":      a.reasoning,
        "approved_by":    a.approved_by,
        "approved_at":    a.approved_at.isoformat() if a.approved_at else None,
        "executed_at":    a.executed_at.isoformat() if a.executed_at else None,
        "error_message":  a.error_message,
        "created_at":     a.created_at.isoformat() if a.created_at else None,
    }


def _execute_action(action: AgentAction) -> tuple:
    """Execute the action (called when human approves)."""
    try:
        if action.action_type == "BLOCK_IP":
            from signature_engine import block_ip_now
            block_ip_now(action.target)
            return True, ""
        elif action.action_type == "MONITOR":
            # No-op, just record
            return True, ""
        elif action.action_type == "ALERT":
            # Already handled by NotificationService when triaged
            return True, ""
        else:
            return False, f"Unknown action_type: {action.action_type}"
    except Exception as e:
        return False, str(e)
