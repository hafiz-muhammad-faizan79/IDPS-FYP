# idps-backend/routers/configuration.py
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Optional

from database import get_db
from models.configuration import (
    SignatureRule, RansomwareRule, AnomalyConfig,
    NetworkInterface, AlertSettings, SystemSettings,
)

from models.network import BlockedIP

from schemas.configuration import (
    SignatureRuleCreate, SignatureRuleUpdate, SignatureRuleOut,
    RansomwareRuleCreate, RansomwareRuleUpdate, RansomwareRuleOut,
    AnomalyConfigUpdate, AnomalyConfigOut,
    NetworkInterfaceUpdate, NetworkInterfaceOut,
    AlertSettingsUpdate, AlertSettingsOut,
    SystemSettingsUpdate, SystemSettingsOut,
)

router = APIRouter(prefix="/api/configuration", tags=["Configuration"])

# ══════════════════════════════════════════════════════════════
# HELPER — get-or-create single-row config tables
# ══════════════════════════════════════════════════════════════
def _get_or_create_singleton(db: Session, Model, default_id: int = 1):
    obj = db.query(Model).filter(Model.id == default_id).first()
    if not obj:
        obj = Model(id=default_id)
        db.add(obj)
        db.commit()
        db.refresh(obj)
    return obj


# ══════════════════════════════════════════════════════════════
# 1. SIGNATURE RULES
# ══════════════════════════════════════════════════════════════
@router.get("/signatures", response_model=list[SignatureRuleOut])
def list_signatures(
    enabled:  Optional[bool] = None,
    severity: Optional[str]  = None,
    search:   Optional[str]  = None,
    db: Session = Depends(get_db),
):
    q = db.query(SignatureRule)
    if enabled  is not None:     q = q.filter(SignatureRule.enabled  == enabled)
    if severity and severity != "All": q = q.filter(SignatureRule.severity == severity)
    if search:
        q = q.filter(
            SignatureRule.name.ilike(f"%{search}%") |
            SignatureRule.id.ilike(f"%{search}%")   |
            SignatureRule.pattern.ilike(f"%{search}%")
        )
    return q.order_by(SignatureRule.id).all()


@router.post("/signatures", response_model=SignatureRuleOut, status_code=201)
def create_signature(body: SignatureRuleCreate, db: Session = Depends(get_db)):
    if db.query(SignatureRule).filter(SignatureRule.id == body.id).first():
        raise HTTPException(400, f"Rule {body.id} already exists")
    rule = SignatureRule(**body.model_dump())
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


@router.patch("/signatures/{rule_id}", response_model=SignatureRuleOut)
def update_signature(rule_id: str, body: SignatureRuleUpdate, db: Session = Depends(get_db)):
    rule = db.query(SignatureRule).filter(SignatureRule.id == rule_id).first()
    if not rule:
        raise HTTPException(404, f"Rule {rule_id} not found")
    for field, val in body.model_dump(exclude_none=True).items():
        setattr(rule, field, val)
    db.commit()
    db.refresh(rule)
    return rule


@router.delete("/signatures/{rule_id}")
def delete_signature(rule_id: str, db: Session = Depends(get_db)):
    rule = db.query(SignatureRule).filter(SignatureRule.id == rule_id).first()
    if not rule:
        raise HTTPException(404, f"Rule {rule_id} not found")
    db.delete(rule)
    db.commit()
    return {"success": True, "deleted": rule_id}


@router.post("/signatures/{rule_id}/toggle", response_model=SignatureRuleOut)
def toggle_signature(rule_id: str, db: Session = Depends(get_db)):
    rule = db.query(SignatureRule).filter(SignatureRule.id == rule_id).first()
    if not rule:
        raise HTTPException(404, f"Rule {rule_id} not found")
    rule.enabled = not rule.enabled
    db.commit()
    db.refresh(rule)
    # Hot-reload engine
    try:
        from signature_engine import reload_rules
        reload_rules()
    except Exception:
        pass
    return rule


# ══════════════════════════════════════════════════════════════
# 2. RANSOMWARE RULES
# ══════════════════════════════════════════════════════════════
@router.get("/ransomware", response_model=list[RansomwareRuleOut])
def list_ransomware(
    enabled:    Optional[bool] = None,
    risk_level: Optional[str]  = None,
    db: Session = Depends(get_db),
):
    q = db.query(RansomwareRule)
    if enabled    is not None:         q = q.filter(RansomwareRule.enabled    == enabled)
    if risk_level and risk_level != "All": q = q.filter(RansomwareRule.risk_level == risk_level)
    return q.order_by(RansomwareRule.id).all()


@router.post("/ransomware", response_model=RansomwareRuleOut, status_code=201)
def create_ransomware(body: RansomwareRuleCreate, db: Session = Depends(get_db)):
    if db.query(RansomwareRule).filter(RansomwareRule.id == body.id).first():
        raise HTTPException(400, f"Rule {body.id} already exists")
    rule = RansomwareRule(**body.model_dump())
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


@router.patch("/ransomware/{rule_id}", response_model=RansomwareRuleOut)
def update_ransomware(rule_id: str, body: RansomwareRuleUpdate, db: Session = Depends(get_db)):
    rule = db.query(RansomwareRule).filter(RansomwareRule.id == rule_id).first()
    if not rule:
        raise HTTPException(404, f"Rule {rule_id} not found")
    for field, val in body.model_dump(exclude_none=True).items():
        setattr(rule, field, val)
    db.commit()
    db.refresh(rule)
    return rule


@router.post("/ransomware/{rule_id}/toggle", response_model=RansomwareRuleOut)
def toggle_ransomware(rule_id: str, db: Session = Depends(get_db)):
    rule = db.query(RansomwareRule).filter(RansomwareRule.id == rule_id).first()
    if not rule:
        raise HTTPException(404, f"Rule {rule_id} not found")
    rule.enabled = not rule.enabled
    db.commit()
    db.refresh(rule)
    return rule


# ══════════════════════════════════════════════════════════════
# 3. ANOMALY DETECTION CONFIG
# ══════════════════════════════════════════════════════════════
@router.get("/anomaly", response_model=AnomalyConfigOut)
def get_anomaly(db: Session = Depends(get_db)):
    return _get_or_create_singleton(db, AnomalyConfig)


@router.patch("/anomaly", response_model=AnomalyConfigOut)
def update_anomaly(body: AnomalyConfigUpdate, db: Session = Depends(get_db)):
    cfg = _get_or_create_singleton(db, AnomalyConfig)
    for field, val in body.model_dump(exclude_none=True).items():
        setattr(cfg, field, val)
    db.commit()
    db.refresh(cfg)
    return cfg


# ══════════════════════════════════════════════════════════════
# 4. NETWORK INTERFACES
# ══════════════════════════════════════════════════════════════
@router.get("/interfaces", response_model=list[NetworkInterfaceOut])
def list_interfaces(db: Session = Depends(get_db)):
    return db.query(NetworkInterface).order_by(NetworkInterface.name).all()


@router.patch("/interfaces/{iface_name}", response_model=NetworkInterfaceOut)
def update_interface(iface_name: str, body: NetworkInterfaceUpdate, db: Session = Depends(get_db)):
    iface = db.query(NetworkInterface).filter(NetworkInterface.name == iface_name).first()
    if not iface:
        raise HTTPException(404, f"Interface {iface_name} not found")
    for field, val in body.model_dump(exclude_none=True).items():
        setattr(iface, field, val)
    db.commit()
    db.refresh(iface)
    return iface


# ══════════════════════════════════════════════════════════════
# 5. BLOCKED IPs
# ══════════════════════════════════════════════════════════════
@router.get("/blocked-ips")
def list_blocked(db: Session = Depends(get_db)):
    return db.query(BlockedIP).order_by(BlockedIP.blocked_at.desc()).all()


@router.post("/blocked-ips")
def block_ip(body: dict, db: Session = Depends(get_db)):
    ip = body.get("ip", "")
    if not ip:
        raise HTTPException(400, "ip is required")
    existing = db.query(BlockedIP).filter(BlockedIP.ip == ip).first()
    if existing:
        return {"success": False, "message": f"{ip} is already blocked"}
    entry = BlockedIP(ip=ip, reason=body.get("reason"), blocked_by=body.get("blocked_by", "admin"))
    db.add(entry)
    db.commit()
    return {"success": True, "message": f"{ip} blocked"}


@router.delete("/blocked-ips/{ip}")
def unblock_ip(ip: str, db: Session = Depends(get_db)):
    entry = db.query(BlockedIP).filter(BlockedIP.ip == ip).first()
    if not entry:
        raise HTTPException(404, f"{ip} not in blocklist")
    db.delete(entry)
    db.commit()
    return {"success": True, "message": f"{ip} unblocked"}


# ══════════════════════════════════════════════════════════════
# 6. ALERT SETTINGS
# ══════════════════════════════════════════════════════════════
@router.get("/alerts", response_model=AlertSettingsOut)
def get_alert_settings(db: Session = Depends(get_db)):
    return _get_or_create_singleton(db, AlertSettings)


@router.patch("/alerts", response_model=AlertSettingsOut)
def update_alert_settings(body: AlertSettingsUpdate, db: Session = Depends(get_db)):
    cfg = _get_or_create_singleton(db, AlertSettings)
    for field, val in body.model_dump(exclude_none=True).items():
        setattr(cfg, field, val)
    db.commit()
    db.refresh(cfg)
    return cfg


# ══════════════════════════════════════════════════════════════
# 7. SYSTEM SETTINGS
# ══════════════════════════════════════════════════════════════
@router.get("/system", response_model=SystemSettingsOut)
def get_system_settings(db: Session = Depends(get_db)):
    return _get_or_create_singleton(db, SystemSettings)


@router.patch("/system", response_model=SystemSettingsOut)
def update_system_settings(body: SystemSettingsUpdate, db: Session = Depends(get_db)):
    cfg = _get_or_create_singleton(db, SystemSettings)
    for field, val in body.model_dump(exclude_none=True).items():
        setattr(cfg, field, val)
    db.commit()
    db.refresh(cfg)
    return cfg


# ══════════════════════════════════════════════════════════════
# 8. SNAPSHOT — hydrate full config page
# ══════════════════════════════════════════════════════════════
@router.get("/snapshot")
def get_snapshot(db: Session = Depends(get_db)):
    return {
        "signatures":  list_signatures(db=db),
        "ransomware":  list_ransomware(db=db),
        "anomaly":     get_anomaly(db=db),
        "interfaces":  list_interfaces(db=db),
        "blocked_ips": list_blocked(db=db),
        "alerts":      get_alert_settings(db=db),
        "system":      get_system_settings(db=db),
    }

# ══════════════════════════════════════════════════════════════
# FRONTEND ALIAS ROUTES — match old URL paths
# ══════════════════════════════════════════════════════════════

# /ransomware/rules → same as /ransomware
@router.get("/ransomware/rules", response_model=list[RansomwareRuleOut])
def list_ransomware_rules(db: Session = Depends(get_db)):
    return list_ransomware(db=db)

# /anomaly/settings → same as /anomaly
@router.get("/anomaly/settings", response_model=AnomalyConfigOut)
def get_anomaly_settings(db: Session = Depends(get_db)):
    return get_anomaly(db=db)

# /signature/status → summary counts of enabled/disabled
@router.get("/signature/status")
def get_signature_status(db: Session = Depends(get_db)):
    from sqlalchemy import func as sqlfunc
    total    = db.query(SignatureRule).count()
    enabled  = db.query(SignatureRule).filter(SignatureRule.enabled == True).count()
    disabled = total - enabled
    last     = db.query(sqlfunc.max(SignatureRule.updated_at)).scalar()
    return {
        "enabled":      True,
        "total":        total,
        "active":       enabled,
        "inactive":     disabled,
        "last_updated": last.isoformat() if last else "2026-01-01T00:00:00",
        "hit_rate":     "N/A",
    }

# /attackers → returns blocked IPs (used by config page attacker section)
@router.get("/attackers")
def get_attackers(db: Session = Depends(get_db)):
    blocked = db.query(BlockedIP).order_by(BlockedIP.blocked_at.desc()).all()
    attackers = [
        {
            "ip":         b.ip,
            "country":    "Unknown",
            "type":       "Blocked",
            "firstSeen":  b.blocked_at.strftime("%Y-%m-%d %H:%M") if b.blocked_at else "N/A",
            "lastSeen":   b.blocked_at.strftime("%Y-%m-%d %H:%M") if b.blocked_at else "N/A",
            "packets":    0,
            "status":     "Blocked",
            "reason":     b.reason or "Manual block",
        }
        for b in blocked
    ]
    return {"attackers": attackers}

# /changelog → returns last 100 audit-style changes (stub for now)
@router.get("/changelog")
def get_changelog(limit: int = 100, db: Session = Depends(get_db)):
    # Returns recent sig + ransomware rule changes ordered by updated_at
    sigs = db.query(SignatureRule).order_by(SignatureRule.updated_at.desc()).limit(limit).all()
    rans = db.query(RansomwareRule).order_by(RansomwareRule.updated_at.desc()).limit(limit).all()
    changelog = []
    for r in sigs:
        changelog.append({"id": r.id, "name": r.name, "type": "Signature", "updated_at": r.updated_at, "enabled": r.enabled})
    for r in rans:
        changelog.append({"id": r.id, "name": r.name, "type": "Ransomware", "updated_at": r.updated_at, "enabled": r.enabled})
    changelog.sort(key=lambda x: x["updated_at"], reverse=True)
    return {"changelog": changelog[:limit]}


# ══════════════════════════════════════════════════════════════
# ATTACKERS — wrapped response with type field
# ══════════════════════════════════════════════════════════════
@router.get("/attackers/list")
def get_attackers_list(db: Session = Depends(get_db)):
    blocked = db.query(BlockedIP).order_by(BlockedIP.blocked_at.desc()).all()
    attackers = [
        {
            "ip":         b.ip,
            "type":       "Blocked",
            "reason":     b.reason or "Manual block",
            "blocked_by": b.blocked_by,
            "blocked_at": b.blocked_at,
            "status":     "Blocked",
        }
        for b in blocked
    ]
    return {"attackers": attackers}


# OVERRIDE — correct shape for frontend
@router.get("/attackers/full")
def get_attackers_full(db: Session = Depends(get_db)):
    blocked = db.query(BlockedIP).order_by(BlockedIP.created_at.desc()).all()
    return {"attackers": [
        {
            "ip":        b.ip,
            "country":   "Unknown",
            "type":      "Blocked",
            "firstSeen": b.blocked_at.strftime("%Y-%m-%d %H:%M") if b.blocked_at else "N/A",
            "lastSeen":  b.blocked_at.strftime("%Y-%m-%d %H:%M") if b.blocked_at else "N/A",
            "packets":   0,
            "status":    "Blocked",
        }
        for b in blocked
    ]}


# ══════════════════════════════════════════════════════════════
# SIGNATURE ENGINE — hot reload + stats
# ══════════════════════════════════════════════════════════════
@router.post("/signatures/reload")
def reload_signatures(db: Session = Depends(get_db)):
    """Hot-reload signature rules into the live engine."""
    try:
        from signature_engine import reload_rules, get_rule_stats
        count = reload_rules()
        return {"success": True, "loaded": count, "message": f"Reloaded {count} rules into engine"}
    except Exception as e:
        raise HTTPException(500, f"Reload failed: {e}")


@router.get("/signatures/stats")
def get_signature_stats(db: Session = Depends(get_db)):
    """Return hit counts per rule from the live engine."""
    try:
        from signature_engine import get_rule_stats
        hits = get_rule_stats()
        rules = db.query(SignatureRule).all()
        return {
            "stats": [
                {
                    "id":      r.id,
                    "name":    r.name,
                    "hits":    hits.get(r.id, 0),
                    "enabled": r.enabled,
                    "action":  r.action,
                }
                for r in rules
            ]
        }
    except Exception as e:
        raise HTTPException(500, str(e))


@router.post("/blocked-ips/enforce")
def enforce_blocked_ips(db: Session = Depends(get_db)):
    """Apply all blocked IPs from DB to iptables."""
    try:
        from signature_engine import block_ip_now
        blocked = db.query(BlockedIP).all()
        count = 0
        for b in blocked:
            block_ip_now(b.ip)
            count += 1
        return {"success": True, "enforced": count, "message": f"Applied {count} IPs to iptables"}
    except Exception as e:
        raise HTTPException(500, str(e))
