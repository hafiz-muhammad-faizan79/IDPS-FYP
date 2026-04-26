# idps-backend/routers/incidents.py
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime
from fastapi import Depends, HTTPException, Request
from auth import require_role
from models.user import User
from database import get_db
from models.incident import Incident, Detection, IncidentTimeline, DetectionIPAction
from schemas.incident import (
    IncidentOut, IncidentAssign, IncidentResolveAll,
    DetectionOut, TimelineEventOut, IPActionRequest,
)

router = APIRouter(prefix="/api/incidents", tags=["Incidents"])

def _now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M")


@router.post("/close/{inc_id}")
def close_incident(
    inc_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "soc_lead")),
):
    inc = db.query(Incident).filter(Incident.id == inc_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail=f"{inc_id} not found")

    # Optional: guard repeated close
    if inc.status == "Closed":
        return {"success": False, "message": f"{inc_id} is already Closed"}

    inc.status = "Closed"
    db.commit()
    db.refresh(inc)

    return {
        "success": True,
        "incident": inc,
        "closed_by": current_user.username,
    }

# ══════════════════════════════════════════════════════════════
# 1. STAT CARDS  — computed live from DB
# ══════════════════════════════════════════════════════════════
@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    total      = db.query(Detection).count()
    anomaly    = db.query(Detection).filter(Detection.det_type   == "Anomaly").count()
    signature  = db.query(Detection).filter(Detection.det_type   == "Signature").count()
    ransomware = db.query(Detection).filter(Detection.det_type   == "Ransomware").count()
    critical   = db.query(Detection).filter(Detection.severity   == "Critical").count()
    return {
        "stats": [
            {"label":"Total Detections",  "value":total,     "sub":"All time",                  "color":"#00d4ff","pulse":False},
            {"label":"Anomaly",           "value":anomaly,   "sub":"Anomaly-based detections",  "color":"#ffbe0b","pulse":False},
            {"label":"Signature",         "value":signature, "sub":"Signature-based detections","color":"#00ff9f","pulse":False},
            {"label":"Ransomware",        "value":ransomware,"sub":"Ransomware patterns",       "color":"#f97316","pulse":False},
            {"label":"Critical Severity", "value":critical,  "sub":"Require immediate action",  "color":"#ff006e","pulse":True },
        ]
    }


# ══════════════════════════════════════════════════════════════
# 2. INCIDENTS
# ══════════════════════════════════════════════════════════════
@router.get("/list")
def list_incidents(
    status:   Optional[str] = None,
    severity: Optional[str] = None,
    analyst:  Optional[str] = None,
    search:   Optional[str] = None,
    db: Session = Depends(get_db),
):
    q = db.query(Incident)
    if status   and status   != "All": q = q.filter(Incident.status   == status)
    if severity and severity != "All": q = q.filter(Incident.severity == severity)
    if analyst  and analyst  != "All": q = q.filter(Incident.analyst  == analyst)
    if search:
        s = f"%{search.lower()}%"
        q = q.filter(Incident.id.ilike(s) | Incident.desc.ilike(s))
    result = q.order_by(Incident.updated_at.desc()).all()
    return {"total": len(result), "incidents": result}


@router.post("/resolve/{inc_id}")
def resolve_incident(inc_id: str, db: Session = Depends(get_db)):
    inc = db.query(Incident).filter(Incident.id == inc_id).first()
    if not inc:
        raise HTTPException(404, f"{inc_id} not found")
    if inc.status in ("Resolved", "Closed"):
        return {"success": False, "message": f"{inc_id} is already {inc.status}"}
    inc.status = "Resolved"
    db.commit()
    db.refresh(inc)
    return {"success": True, "incident": inc}


@router.post("/close/{inc_id}")
def close_incident(inc_id: str, db: Session = Depends(get_db)):
    inc = db.query(Incident).filter(Incident.id == inc_id).first()
    if not inc:
        raise HTTPException(404, f"{inc_id} not found")
    inc.status = "Closed"
    db.commit()
    db.refresh(inc)
    return {"success": True, "incident": inc}


@router.post("/assign/{inc_id}")
def assign_incident(
    inc_id: str,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "soc_lead")),
):
    inc = db.query(Incident).filter(Incident.id == inc_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail=f"{inc_id} not found")

    analyst = payload.get("analyst")
    if not analyst:
        raise HTTPException(status_code=400, detail="analyst is required")

    inc.analyst = analyst
    inc.status = "In Progress"
    db.commit()
    db.refresh(inc)

    return {"success": True, "incident": inc, "assigned_by": current_user.username}


@router.post("/resolve-all")
def resolve_all_incidents(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "soc_lead")),
):
    ids = payload.get("ids", [])
    if not isinstance(ids, list):
        raise HTTPException(status_code=400, detail="ids must be a list")

    resolved = []
    for inc in db.query(Incident).filter(Incident.id.in_(ids)).all():
        if inc.status not in ("Resolved", "Closed"):
            inc.status = "Resolved"
            resolved.append(inc.id)

    db.commit()
    return {
        "resolved": resolved,
        "count": len(resolved),
        "resolved_by": current_user.username,
    }

@router.get("/timeline/{inc_id}")
def get_timeline(inc_id: str, db: Session = Depends(get_db)):
    events = db.query(IncidentTimeline)\
               .filter(IncidentTimeline.incident_id == inc_id)\
               .order_by(IncidentTimeline.id).all()
    return {"inc_id": inc_id, "timeline": events}


# ══════════════════════════════════════════════════════════════
# 3. DETECTIONS
# ══════════════════════════════════════════════════════════════
@router.get("/detections")
def list_detections(
    det_type:  Optional[str] = None,
    severity:  Optional[str] = None,
    search:    Optional[str] = None,
    db: Session = Depends(get_db),
):
    q = db.query(Detection)
    if det_type and det_type != "All": q = q.filter(Detection.det_type  == det_type)
    if severity and severity != "All": q = q.filter(Detection.severity  == severity)
    if search:
        s = f"%{search}%"
        q = q.filter(
            Detection.src_ip.ilike(s)   |
            Detection.dst_ip.ilike(s)   |
            Detection.protocol.ilike(s)
        )
    result = q.order_by(Detection.id.desc()).all()
    return {"total": len(result), "detections": result}


@router.post("/detections/block")
def block_ip_from_detection(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "soc_lead")),
):
    ip = payload.get("ip")
    if not ip:
        raise HTTPException(status_code=400, detail="ip is required")

    # TODO: your existing block logic here
    return {"success": True, "message": f"IP {ip} blocked", "by": current_user.username}

@router.post("/detections/whitelist")
def whitelist_ip_from_detection(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "soc_lead")),
):
    ip = payload.get("ip")
    if not ip:
        raise HTTPException(status_code=400, detail="ip is required")

    # TODO: your existing whitelist logic here
    return {"success": True, "message": f"IP {ip} whitelisted", "by": current_user.username}


# ══════════════════════════════════════════════════════════════
# 4. CHARTS — computed live from DB
# ══════════════════════════════════════════════════════════════
@router.get("/charts")
def get_charts(db: Session = Depends(get_db)):
    from sqlalchemy import func as sqlfunc

    # Donut — count per det_type
    donut_colors = {"Signature":"#00ff9f","Anomaly":"#ffbe0b","Ransomware":"#f97316"}
    donut_rows = db.query(Detection.det_type, sqlfunc.count(Detection.id))\
                   .group_by(Detection.det_type).all()
    donut = [{"label":row[0],"value":row[1],"color":donut_colors.get(row[0],"#94a3b8")} for row in donut_rows]

    # Bars — count per severity
    bar_colors = {"Info":"#94a3b8","Low":"#00ff9f","Medium":"#ffbe0b","High":"#f97316","Critical":"#ff006e"}
    bar_rows = db.query(Detection.severity, sqlfunc.count(Detection.id))\
                 .group_by(Detection.severity).all()
    bars = [{"label":row[0],"value":row[1],"color":bar_colors.get(row[0],"#94a3b8")} for row in bar_rows]

    return {"donut": donut, "severity_bars": bars}


# ══════════════════════════════════════════════════════════════
# 5. SNAPSHOT
# ══════════════════════════════════════════════════════════════
@router.get("/snapshot")
def get_snapshot(db: Session = Depends(get_db)):
    return {
        "stats":      get_stats(db=db),
        "incidents":  list_incidents(db=db),
        "detections": list_detections(db=db),
        "charts":     get_charts(db=db),
    }