# idps-backend/routers/audits.py
from fastapi import APIRouter, Query, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func as sqlfunc
from typing import Optional
from datetime import datetime

from database import get_db
from models.audit import AuditLog, MaliciousIP
from models.incident import Detection, Incident

router = APIRouter(prefix="/api/audits", tags=["Audits"])

TREND_DATA = {
    "24h": [4200,3800,5100,4600,5800,6200,5500,6800,7200,6100,5900,7400],
    "7d":  [31000,28000,35000,42000,38000,45000,51000],
    "30d": [120000,135000,128000,142000,158000,149000,165000,172000,160000,
            178000,182000,195000,188000,202000,210000],
}

SPARKLINES = [
    [40,55,48,62,58,71,65],
    [88,72,80,75,82,78,85],
    [12,18,15,22,28,24,31],
    [33,41,38,45,42,50,47],
]


# ══════════════════════════════════════════════════════════════
# 1. SUMMARY — computed from DB
# ══════════════════════════════════════════════════════════════
@router.get("/summary")
def get_summary(db: Session = Depends(get_db)):
    total      = db.query(Detection).count()
    resolved   = db.query(Incident).filter(Incident.status.in_(["Resolved","Closed"])).count()
    malicious  = db.query(Detection).filter(Detection.classification == "Malicious").count()
    suspicious = db.query(Detection).filter(Detection.classification == "Suspicious").count()
    return {
        "metrics": [
            {"label":"Total Alerts",       "value":total,     "change":"+12.4%","up":True, "color":"#00d4ff","sub":"All detections",       "spark":SPARKLINES[0]},
            {"label":"Incidents Resolved", "value":resolved,  "change":"+8.1%", "up":True, "color":"#00ff9f","sub":"Closed incidents",      "spark":SPARKLINES[1]},
            {"label":"Malicious Traffic",  "value":malicious, "change":"+22.7%","up":True, "color":"#ff006e","sub":"Confirmed threats",      "spark":SPARKLINES[2]},
            {"label":"Suspicious Traffic", "value":suspicious,"change":"-4.3%", "up":False,"color":"#ffbe0b","sub":"Flagged for review",     "spark":SPARKLINES[3]},
        ]
    }


# ══════════════════════════════════════════════════════════════
# 2. TREND
# ══════════════════════════════════════════════════════════════
@router.get("/trend")
def get_trend(
    period: str = Query("7d"),
    db: Session = Depends(get_db),
):
    if period not in TREND_DATA:
        period = "7d"

    # Compute pie from real DB data
    rows = db.query(Detection.det_type, sqlfunc.count(Detection.id))\
             .group_by(Detection.det_type).all()
    total = db.query(Detection).count() or 1
    colors = {"Signature":"#00ff9f","Anomaly":"#ffbe0b","Ransomware":"#f97316"}
    pie = [
        {"label":r[0],"value":r[1],"color":colors.get(r[0],"#94a3b8"),
         "pct": round(r[1]/total*100,1)}
        for r in rows
    ]
    return {
        "period": period,
        "trend":  TREND_DATA[period],
        "pie":    pie,
        "total":  total,
    }


# ══════════════════════════════════════════════════════════════
# 3. DETECTION DISTRIBUTION — computed from DB
# ══════════════════════════════════════════════════════════════
@router.get("/detection-distribution")
def get_detection_distribution(db: Session = Depends(get_db)):
    rows  = db.query(Detection.det_type, sqlfunc.count(Detection.id))\
              .group_by(Detection.det_type).all()
    total = db.query(Detection).count() or 1
    colors = {"Anomaly":"#ffbe0b","Signature":"#00ff9f","Ransomware":"#f97316"}
    descs  = {
        "Anomaly":   "Behavioral baseline deviation — traffic anomalies and unusual patterns flagged",
        "Signature": "Pattern-matched against active signature rules covering SQL, XSS, DDoS and malware",
        "Ransomware":"Encryption pattern analysis, file system monitoring and registry change detection",
    }
    return {
        "distributions": [
            {"label":f"{r[0]} Detection","pct":round(r[1]/total*100),
             "color":colors.get(r[0],"#94a3b8"),"desc":descs.get(r[0],"")}
            for r in rows
        ]
    }


# ══════════════════════════════════════════════════════════════
# 4. TRAFFIC BY PROTOCOL — static (no protocol table yet)
# ══════════════════════════════════════════════════════════════
@router.get("/traffic-protocol")
def get_traffic_protocol():
    return {
        "protocols": [
            {"proto":"TCP",   "pct":45,"packets":1842301,"color":"#00d4ff","status":"HIGH"    },
            {"proto":"UDP",   "pct":22,"packets":901220, "color":"#00ff9f","status":"NORMAL"  },
            {"proto":"HTTP",  "pct":18,"packets":738540, "color":"#ffbe0b","status":"ELEVATED"},
            {"proto":"HTTPS", "pct":12,"packets":491820, "color":"#a78bfa","status":"NORMAL"  },
            {"proto":"Other", "pct":3, "packets":122960, "color":"#64748b","status":"LOW"     },
        ]
    }


# ══════════════════════════════════════════════════════════════
# 5. SEVERITY OUTCOMES — computed from DB
# ══════════════════════════════════════════════════════════════
@router.get("/severity-outcomes")
def get_severity_outcomes(db: Session = Depends(get_db)):
    colors = {"Critical":"#ff006e","High":"#f97316","Medium":"#ffbe0b","Low":"#00ff9f"}
    outcomes = []
    for sev in ["Critical","High","Medium"]:
        total    = db.query(Incident).filter(Incident.severity == sev).count()
        resolved = db.query(Incident).filter(
            Incident.severity == sev,
            Incident.status.in_(["Resolved","Closed"])
        ).count()
        if total > 0:
            outcomes.append({
                "label":    sev,
                "count":    total,
                "resolved": round(resolved / total * 100),
                "color":    colors[sev],
            })
    return {"outcomes": outcomes}


# ══════════════════════════════════════════════════════════════
# 6. MALICIOUS IPs — from DB
# ══════════════════════════════════════════════════════════════
@router.get("/malicious-ips")
def get_malicious_ips(
    search: Optional[str] = None,
    db: Session = Depends(get_db),
):
    q = db.query(MaliciousIP).order_by(MaliciousIP.events.desc())
    if search:
        q = q.filter(
            MaliciousIP.ip.ilike(f"%{search}%") |
            MaliciousIP.type.ilike(f"%{search}%")
        )
    rows = q.all()
    return {
        "total": len(rows),
        "ips": [
            {"ip":r.ip,"events":r.events,"type":r.type,
             "avgSev":r.avg_sev,"protocol":r.protocol,
             "country":r.country,"lastSeen":r.last_seen}
            for r in rows
        ]
    }


# ══════════════════════════════════════════════════════════════
# 7. AUDIT LOGS — from DB
# ══════════════════════════════════════════════════════════════
@router.get("/logs")
def get_audit_logs(
    actor:      Optional[str] = None,
    changeType: Optional[str] = None,
    search:     Optional[str] = None,
    sort_asc:   bool          = False,
    limit:      int           = 100,
    db: Session = Depends(get_db),
):
    q = db.query(AuditLog)
    if actor and actor != "All":
        q = q.filter(AuditLog.actor == actor)
    if changeType and changeType != "All":
        q = q.filter(AuditLog.change_type == changeType)
    if search:
        q = q.filter(
            AuditLog.target.ilike(f"%{search}%") |
            AuditLog.actor.ilike(f"%{search}%")
        )
    order = AuditLog.timestamp.asc() if sort_asc else AuditLog.timestamp.desc()
    rows = q.order_by(order).limit(limit).all()
    return {
        "total": len(rows),
        "logs": [
            {"id":r.id,"timestamp":r.timestamp,"actor":r.actor,
             "changeType":r.change_type,"target":r.target,
             "action":r.action,"details":r.details,
             "rolled_back":r.rolled_back}
            for r in rows
        ]
    }


@router.post("/logs/{log_id}/rollback")
def rollback_log(log_id: str, db: Session = Depends(get_db)):
    log = db.query(AuditLog).filter(AuditLog.id == log_id).first()
    if not log:
        raise HTTPException(404, f"{log_id} not found")
    if log.rolled_back:
        return {"success": False, "message": f"{log_id} already rolled back"}

    log.rolled_back = True

    # Generate new AUD ID
    max_num = db.query(sqlfunc.max(AuditLog.id)).scalar()
    try:
        next_num = int(max_num.split("-")[1]) + 1
    except:
        next_num = 99
    new_id = f"AUD-{next_num:03d}"

    new_entry = AuditLog(
        id=new_id,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M"),
        actor="admin",
        change_type="Modified",
        target=log.target,
        action=f"Rollback of {log_id}",
        details=f"Reverted: {log.details}",
        rolled_back=False,
    )
    db.add(new_entry)
    db.commit()
    db.refresh(new_entry)
    return {
        "success": True,
        "message": f"Rollback triggered for {log_id}",
        "new_entry": {
            "id":new_entry.id,"timestamp":new_entry.timestamp,
            "actor":new_entry.actor,"changeType":new_entry.change_type,
            "target":new_entry.target,"action":new_entry.action,
            "details":new_entry.details,"rolled_back":new_entry.rolled_back,
        }
    }


# ══════════════════════════════════════════════════════════════
# 8. SNAPSHOT
# ══════════════════════════════════════════════════════════════
@router.get("/snapshot")
def get_snapshot(db: Session = Depends(get_db)):
    return {
        "summary":                get_summary(db=db),
        "trend":                  get_trend(db=db),
        "detection_distribution": get_detection_distribution(db=db),
        "traffic_protocol":       get_traffic_protocol(),
        "severity_outcomes":      get_severity_outcomes(db=db),
        "malicious_ips":          get_malicious_ips(db=db),
        "audit_logs":             get_audit_logs(db=db),
    }