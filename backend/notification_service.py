"""
notification_service.py
=======================
CyGuardian-X Notification Service

Dispatches alerts on Critical/High severity threats:
  • Email (admin + soc_lead users)
  • In-app notification (stored in DB, fetched via /api/notifications)
  • Rate limiting (max 1 email per IP per 5 min)
"""

import json
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List

from email_service import send_async, BASE_STYLE, FRONTEND_URL

# ── Severity policy ───────────────────────────────────────────
TRIGGER_SEVERITIES = ("Critical", "High")
EMAIL_RECIPIENTS_ROLES = ("admin", "soc_lead")

# ── Rate limit (avoid email spam from same IP) ────────────────
_email_cache: Dict[str, float] = {}     # src_ip -> last sent timestamp
_email_lock = threading.Lock()
EMAIL_COOLDOWN_SECONDS = 300            # 5 minutes


def _can_send_email(src_ip: str) -> bool:
    now = time.time()
    with _email_lock:
        last = _email_cache.get(src_ip, 0)
        if now - last < EMAIL_COOLDOWN_SECONDS:
            return False
        _email_cache[src_ip] = now
    return True


# ══════════════════════════════════════════════════════════════
# RECIPIENT LOOKUP
# ══════════════════════════════════════════════════════════════
def _get_recipients(db) -> List[Dict]:
    """Return list of admin + soc_lead users (verified, active)."""
    from models.user import User
    try:
        users = db.query(User).filter(
            User.role.in_(EMAIL_RECIPIENTS_ROLES),
            User.is_active == True,
        ).all()
        return [{"username": u.username, "email": u.email, "name": u.name} for u in users]
    except Exception as e:
        print(f"[NOTIFY] Recipient lookup failed: {e}")
        return []


# ══════════════════════════════════════════════════════════════
# EMAIL TEMPLATE
# ══════════════════════════════════════════════════════════════
def _build_email(decision: Dict[str, Any], recipient_name: str) -> tuple:
    """Build subject + HTML body for a threat email."""
    severity = decision.get("severity", "High")
    category = decision.get("category", "THREAT")
    src_ip   = decision.get("src_ip", "unknown")
    reason   = decision.get("reason", "Threat detected by CyGuardian-X")
    conf     = decision.get("confidence", 0)
    action   = decision.get("recommended", "ALERT")
    when     = decision.get("timestamp", datetime.utcnow().isoformat())

    sev_color = {"Critical": "#ff006e", "High": "#f59e0b"}.get(severity, "#00d4ff")

    subject = f"[CyGuardian-X] {severity.upper()} — {category} from {src_ip}"

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">{BASE_STYLE}</head><body>
<div class="wrap"><div class="card" style="border-color:{sev_color};">
    <div class="logo">CyGuardian-X</div>
    <div class="subtitle" style="color:{sev_color};">{severity.upper()} THREAT DETECTED</div>

    <h2 style="color:{sev_color};">[{category}]</h2>
    <p>Hi {recipient_name},</p>
    <p>A <strong style="color:{sev_color};">{severity}</strong> severity threat was detected by the CyGuardian-X intrusion detection system.</p>

    <table style="width:100%; margin:24px 0; border-collapse:collapse;">
        <tr><td style="padding:8px 0; color:#94a3b8;">Source IP:</td>
            <td style="padding:8px 0; color:#00d4ff; font-family:monospace;">{src_ip}</td></tr>
        <tr><td style="padding:8px 0; color:#94a3b8;">Category:</td>
            <td style="padding:8px 0; color:#e2e8f0;">{category}</td></tr>
        <tr><td style="padding:8px 0; color:#94a3b8;">Severity:</td>
            <td style="padding:8px 0; color:{sev_color}; font-weight:bold;">{severity}</td></tr>
        <tr><td style="padding:8px 0; color:#94a3b8;">Confidence:</td>
            <td style="padding:8px 0; color:#e2e8f0;">{conf:.1f}%</td></tr>
        <tr><td style="padding:8px 0; color:#94a3b8;">Recommended:</td>
            <td style="padding:8px 0; color:{sev_color}; font-weight:bold;">{action}</td></tr>
        <tr><td style="padding:8px 0; color:#94a3b8;">Detected at:</td>
            <td style="padding:8px 0; color:#e2e8f0; font-family:monospace; font-size:11px;">{when}</td></tr>
    </table>

    <p style="background:rgba(0,212,255,0.05); border-left:3px solid #00d4ff; padding:12px; color:#cbd5e1; font-size:13px;">
        <strong>Reason:</strong><br>{reason}
    </p>

    <p style="text-align:center; margin:24px 0;">
        <a href="{FRONTEND_URL}/dashboard" class="btn">VIEW IN DASHBOARD</a>
    </p>

    <div class="footer">
        CyGuardian-X • Automated security alert • Do not reply<br>
        You are receiving this because your role ({"/".join(EMAIL_RECIPIENTS_ROLES)}) handles security incidents.
    </div>
</div></div>
</body></html>"""
    return subject, html


# ══════════════════════════════════════════════════════════════
# MAIN DISPATCH
# ══════════════════════════════════════════════════════════════
def dispatch(decision: Dict[str, Any]):
    """
    Called from correlation_engine when a Critical/High threat is detected.
    Stores in-app notification AND sends email if rate-limit allows.
    """
    severity = decision.get("severity")
    if severity not in TRIGGER_SEVERITIES:
        return

    src_ip = decision.get("src_ip", "unknown")

    try:
        from database import SessionLocal
        from models.notification import Notification
        db = SessionLocal()

        recipients   = _get_recipients(db)
        should_email = _can_send_email(src_ip)
        title        = f"[{decision.get('category','THREAT')}] {severity} — {src_ip}"
        reason       = decision.get("reason", "Threat detected")
        category     = decision.get("category", "")

        # Persist one notification per recipient (so each user sees their own)
        for r in recipients:
            n = Notification(
                recipient        = r["username"],
                severity         = severity,
                title            = title,
                message          = reason,
                src_ip           = src_ip,
                category         = category,
                correlation_data = json.dumps(decision, default=str),
                email_sent       = should_email,
                read             = False,
            )
            db.add(n)
        db.commit()
        db.close()

        # Send emails (in background, non-blocking)
        if should_email:
            for r in recipients:
                subject, html = _build_email(decision, r["name"] or r["username"])
                send_async(r["email"], subject, html)
            print(f"[NOTIFY] Dispatched {severity} alert to {len(recipients)} recipients ({src_ip})")
        else:
            print(f"[NOTIFY] Rate-limited email for {src_ip}, in-app only")

    except Exception as e:
        print(f"[NOTIFY] Dispatch failed: {e}")


def get_notifications_for_user(db, username: str, limit: int = 50, only_unread: bool = False) -> List[Dict]:
    """Return notifications for a specific user."""
    from models.notification import Notification
    q = db.query(Notification).filter(Notification.recipient == username)
    if only_unread:
        q = q.filter(Notification.read == False)
    rows = q.order_by(Notification.created_at.desc()).limit(limit).all()
    return [{
        "id":         n.id,
        "severity":   n.severity,
        "title":      n.title,
        "message":    n.message,
        "src_ip":     n.src_ip,
        "category":   n.category,
        "email_sent": n.email_sent,
        "read":       n.read,
        "created_at": n.created_at.isoformat() if n.created_at else None,
    } for n in rows]


def count_unread(db, username: str) -> int:
    from models.notification import Notification
    return db.query(Notification).filter(
        Notification.recipient == username,
        Notification.read == False,
    ).count()


def mark_read(db, username: str, notif_id: int) -> bool:
    from models.notification import Notification
    n = db.query(Notification).filter(
        Notification.id == notif_id,
        Notification.recipient == username,
    ).first()
    if not n:
        return False
    n.read = True
    db.commit()
    return True


def mark_all_read(db, username: str) -> int:
    from models.notification import Notification
    count = db.query(Notification).filter(
        Notification.recipient == username,
        Notification.read == False,
    ).update({"read": True})
    db.commit()
    return count
