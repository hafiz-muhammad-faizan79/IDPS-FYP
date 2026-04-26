# idps-backend/routers/dashboard.py
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func as sqlfunc

from database import get_db
from models.incident import Incident, Detection
from models.configuration import SignatureRule, RansomwareRule
from models.network import BlockedIP
from models.audit import AuditLog
from models.network import NetworkAlert

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


# ══════════════════════════════════════════════════════════════
# 1. STAT CARDS
# ══════════════════════════════════════════════════════════════
@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    from models.user import User
    total_detections = db.query(Detection).count()
    active_incidents = db.query(Incident).filter(
        Incident.status.in_(["Open", "In Progress"])
    ).count()
    user_count = db.query(User).count()

    return {
        "total_users":    {"value": user_count,        "trend": "up",   "change": "+12%", "sub": "Across all roles"   },
        "active_attacks": {"value": active_incidents,  "trend": "down", "change": "-3%",  "sub": "Requires attention" },
        "network_flows":  {"value": 47832,             "trend": "up",   "change": "+12%", "sub": "Packets/sec live"   },
        "detections":     {"value": total_detections,  "trend": "up",   "change": "+12%", "sub": "Last 24 hours total"},
    }

# ══════════════════════════════════════════════════════════════
# 2. DETECTION SUMMARY — donut chart
# ══════════════════════════════════════════════════════════════
@router.get("/detections")
def get_detections(db: Session = Depends(get_db)):
    from sqlalchemy import func as sqlfunc
    total  = db.query(Detection).count() or 1
    mal    = db.query(Detection).filter(Detection.classification == "Malicious").count()
    sus    = db.query(Detection).filter(Detection.classification == "Suspicious").count()
    normal = db.query(Detection).filter(Detection.classification == "Normal").count()
    return {
        "total": total,
        "categories": [
            {"label":"Normal",     "value":normal, "pct":round(normal/total*100), "color":"#00ff9f"},
            {"label":"Suspicious", "value":sus,    "pct":round(sus/total*100),    "color":"#ffbe0b"},
            {"label":"Malicious",  "value":mal,    "pct":round(mal/total*100),    "color":"#ff006e"},
        ]
    }

    
# ══════════════════════════════════════════════════════════════
# 3. ALERT TRENDS — severity breakdown
# ══════════════════════════════════════════════════════════════
@router.get("/alert-trends")
def get_alert_trends(db: Session = Depends(get_db)):
    rows = db.query(Detection.severity, sqlfunc.count(Detection.id))\
             .group_by(Detection.severity).all()
    colors = {
        "Critical": "#ff006e",
        "High":     "#f97316",
        "Medium":   "#ffbe0b",
        "Low":      "#00ff9f",
        "Info":     "#94a3b8",
    }
    # Sparkline placeholder — 7 points per severity
    sparks = {
        "Critical": [3,5,4,7,6,8,9],
        "High":     [8,6,9,7,10,8,11],
        "Medium":   [12,10,14,11,13,15,12],
        "Low":      [5,7,6,8,5,9,7],
        "Info":     [2,3,2,4,3,2,3],
    }
    return {
        "trends": [
            {
                "severity": r[0],
                "count":    r[1],
                "color":    colors.get(r[0], "#94a3b8"),
                "spark":    sparks.get(r[0], [1,1,1,1,1,1,1]),
            }
            for r in rows
        ]
    }


# ══════════════════════════════════════════════════════════════
# 4. USERS BY ROLE — computed from incidents analysts
# ══════════════════════════════════════════════════════════════
@router.get("/users-by-role")
def get_users_by_role(db: Session = Depends(get_db)):
    from models.user import User
    rows = db.query(User.role, sqlfunc.count(User.id)).group_by(User.role).all()
    total = db.query(User).count() or 1
    colors = {"admin":"#a78bfa","soc_lead":"#00d4ff","analyst":"#00ff9f"}
    role_labels = {"admin":"Admin","soc_lead":"SOC Lead","analyst":"SOC Analyst"}
    return {
        "total": total,
        "roles": [
            {
                "role":  role_labels.get(r[0], r[0]),
                "count": r[1],
                "color": colors.get(r[0], "#94a3b8"),
                "pct":   round(r[1]/total*100),
            }
            for r in rows
        ]
    }

# ══════════════════════════════════════════════════════════════
# 5. RECENT USERS — latest incident actors
# ══════════════════════════════════════════════════════════════
@router.get("/recent-users")
def get_recent_users(db: Session = Depends(get_db)):
    from models.user import User
    users = db.query(User).order_by(User.last_login.desc().nullslast()).limit(5).all()
    recent = [
        {
            "name":        u.name,
            "email":       u.email,
            "role":        u.role,
            "status":      "online" if i == 0 else "away",
            "avatar":      u.avatar or u.name[:2].upper(),
            "last_active": u.last_login.strftime("%H:%M ago") if u.last_login else "Never",
        }
        for i, u in enumerate(users)
    ]
    # last created and last deactivated
    last_created = db.query(User).order_by(User.created_at.desc()).first()
    last_deact   = db.query(User).filter(User.is_active == False).order_by(User.updated_at.desc()).first()
    return {
        "recent": recent,
        "last_created": {
            "name":   last_created.name   if last_created else "N/A",
            "email":  last_created.email  if last_created else "N/A",
            "role":   last_created.role   if last_created else "N/A",
            "avatar": last_created.avatar if last_created else "N/A",
            "time":   last_created.created_at.strftime("%b %d, %H:%M") if last_created else "N/A",
        },
        "last_deactivated": {
            "name":   last_deact.name   if last_deact else "John Doe",
            "email":  last_deact.email  if last_deact else "john@soc.local",
            "role":   last_deact.role   if last_deact else "Guest",
            "avatar": last_deact.avatar if last_deact else "JD",
            "time":   "N/A",
        },
    }

# ══════════════════════════════════════════════════════════════
# 6. QUICK ACCESS — live counts for nav cards
# ══════════════════════════════════════════════════════════════
@router.get("/quick-access")
def get_quick_access(db: Session = Depends(get_db)):
    from models.user import User
    from models.configuration import SignatureRule
    from models.audit import AuditLog

    critical = db.query(Incident).filter(Incident.status.in_(["Open","In Progress"]),Incident.severity == "Critical").count()
    sig_count = db.query(SignatureRule).count()
    user_count = db.query(User).count()
    audit_count = db.query(AuditLog).count()

    return {
        "manage_users":           {"badge": f"{user_count} users",       "count": user_count  },
        "security_configuration": {"badge": f"{sig_count} rules",        "count": sig_count   },
        "network_monitoring":     {"badge": "32 sensors",                "count": 32          },
        "alerts_incidents":       {"badge": f"{critical} critical",      "count": critical    },
        "audit_reports":          {"badge": f"{audit_count} entries",    "count": audit_count },
    }