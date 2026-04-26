"""
routers/network.py — DB-backed persistent logs + alerts, live WebSocket unchanged
"""
import asyncio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, Depends
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime

from database import get_db
from models.network import NetworkLog, NetworkAlert
from models.network import BlockedIP
from network_monitor import state, MY_IP

router = APIRouter(prefix="/api/network", tags=["Network Monitoring"])


# ══════════════════════════════════════════════════════════════
# LIVE REST ENDPOINTS — still from in-memory state
# ══════════════════════════════════════════════════════════════

@router.get("/snapshot")
def get_snapshot():
    return state.snapshot()


@router.get("/stats")
def get_stats():
    with state.lock:
        return {
            "total_packets":      state.total_packets,
            "pps":                state.pps,
            "bandwidth":          state.bandwidth,
            "upload":             state.upload,
            "download":           state.download,
            "active_connections": state.active_connections,
            "threats_detected":   state.threats_detected,
            "threats_blocked":    state.threats_blocked,
        }


@router.get("/connections")
def get_connections(
    status:   Optional[str] = Query(None),
    protocol: Optional[str] = Query(None),
    search:   Optional[str] = Query(None),
    limit:    int           = Query(40),
):
    with state.lock:
        conns = list(state.connections)
    if status:   conns = [c for c in conns if c["status"].lower()   == status.lower()]
    if protocol: conns = [c for c in conns if c["protocol"].lower() == protocol.lower()]
    if search:   conns = [c for c in conns if search in c["srcIp"]  or search in c["dstIp"]]
    return {"total": len(conns), "connections": conns[:limit]}


@router.get("/health")
def get_health():
    with state.lock:
        return {
            "cpu":       state.cpu,
            "mem":       state.mem,
            "pkt_loss":  state.pkt_loss,
            "latency":   state.latency,
            "interface": "wlp0s20f3",
            "my_ip":     MY_IP,
            "services": [
                {"name": "Network Adapter",  "status": "ONLINE",  "ok": True},
                {"name": "IDS Engine",       "status": "ACTIVE",  "ok": True},
                {"name": "Firewall",         "status": "ACTIVE",  "ok": True},
                {"name": "Packet Inspector", "status": "RUNNING", "ok": True},
            ]
        }


@router.get("/proto-dist")
def get_proto_dist():
    with state.lock:
        return {"protocols": [{"proto": k, "pct": v} for k, v in state.proto_dist.items()]}


@router.get("/traffic-history")
def get_traffic_history():
    with state.lock:
        return {
            "pps_history": list(state.pps_history),
            "bw_history":  list(state.bw_history),
        }


@router.get("/traffic-type")
def get_traffic_type():
    colors = ["#00d4ff", "#00ff9f", "#ffbe0b", "#ff006e"]
    with state.lock:
        return {
            "breakdown": [
                {"label": k, "value": v, "color": colors[i]}
                for i, (k, v) in enumerate(state.traffic_type.items())
            ]
        }


# ══════════════════════════════════════════════════════════════
# DB-BACKED ALERTS
# ══════════════════════════════════════════════════════════════

@router.get("/alerts")
def get_alerts(
    severity: Optional[str] = Query(None),
    limit:    int           = Query(20),
    db: Session = Depends(get_db),
):
    # First check DB for persisted alerts
    q = db.query(NetworkAlert).order_by(NetworkAlert.created_at.desc())
    if severity:
        q = q.filter(NetworkAlert.severity == severity.capitalize())
    db_alerts = q.limit(limit).all()

    if db_alerts:
        return {
            "total": len(db_alerts),
            "alerts": [
                {
                    "id":       a.id,
                    "severity": a.severity,
                    "srcIp":    a.src_ip,
                    "dstIp":    a.dst_ip,
                    "message":  a.message,
                    "protocol": a.protocol,
                    "port":     a.port,
                    "resolved": a.resolved,
                    "time":     a.created_at.strftime("%H:%M:%S"),
                }
                for a in db_alerts
            ]
        }

    # Fallback to in-memory if DB is empty
    with state.lock:
        alerts = list(state.alerts)
    if severity:
        alerts = [a for a in alerts if a["severity"].lower() == severity.lower()]
    return {"total": len(alerts), "alerts": alerts[:limit]}


@router.post("/alerts/resolve/{alert_id}")
def resolve_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(NetworkAlert).filter(NetworkAlert.id == alert_id).first()
    if not alert:
        return {"success": False, "message": "Alert not found"}
    alert.resolved = True
    db.commit()
    return {"success": True, "message": f"Alert {alert_id} resolved"}


@router.post("/clear-alerts")
def clear_alerts(db: Session = Depends(get_db)):
    # Clear both in-memory and DB
    with state.lock:
        count = len(state.alerts)
        state.alerts.clear()
    db.query(NetworkAlert).delete()
    db.commit()
    return {"success": True, "cleared": count}


# ══════════════════════════════════════════════════════════════
# DB-BACKED LOGS
# ══════════════════════════════════════════════════════════════

@router.get("/logs")
def get_logs(
    status: Optional[str] = Query(None),
    event:  Optional[str] = Query(None),
    limit:  int           = Query(100),
    db: Session = Depends(get_db),
):
    q = db.query(NetworkLog).order_by(NetworkLog.created_at.desc())
    if status: q = q.filter(NetworkLog.status == status.upper())
    if event:  q = q.filter(NetworkLog.event  == event.upper())
    db_logs = q.limit(limit).all()

    if db_logs:
        return {
            "total": len(db_logs),
            "logs": [
                {
                    "id":      l.id,
                    "status":  l.status,
                    "srcIp":   l.src_ip,
                    "event":   l.event,
                    "result":  l.result,
                    "message": l.message,
                    "time":    l.created_at.strftime("%H:%M:%S"),
                }
                for l in db_logs
            ]
        }

    # Fallback to in-memory
    with state.lock:
        logs = list(state.logs)
    if status: logs = [l for l in logs if l["status"] == status.upper()]
    if event:  logs = [l for l in logs if l["event"]  == event.upper()]
    return {"total": len(logs), "logs": logs[:limit]}


@router.post("/clear-logs")
def clear_logs(db: Session = Depends(get_db)):
    with state.lock:
        count = len(state.logs)
        state.logs.clear()
    db.query(NetworkLog).delete()
    db.commit()
    return {"success": True, "cleared": count}


# ══════════════════════════════════════════════════════════════
# DB-BACKED BLOCK / WHITELIST
# ══════════════════════════════════════════════════════════════

@router.post("/block-ip")
def block_ip(payload: dict, db: Session = Depends(get_db)):
    ip = payload.get("ip", "unknown")

    # Persist to DB
    existing = db.query(BlockedIP).filter(BlockedIP.ip == ip).first()
    if not existing:
        db.add(BlockedIP(ip=ip, reason="Blocked via network monitor", blocked_by="analyst"))
        db.commit()

    # Also log the action
    log = NetworkLog(status="BLOCKED", src_ip=ip, event="BLOCKED", result="SUCCESS",
                     message="Manually blocked via dashboard")
    db.add(log)
    db.commit()

    # Update in-memory state
    with state.lock:
        state.threats_blocked += 1
        for c in state.connections:
            if c["srcIp"] == ip:
                c["status"]  = "Blocked"
                c["flagged"] = True

    return {"success": True, "message": f"IP {ip} blocked"}


@router.post("/whitelist-ip")
def whitelist_ip(payload: dict, db: Session = Depends(get_db)):
    ip = payload.get("ip", "unknown")

    # Log the action
    log = NetworkLog(status="ALLOWED", src_ip=ip, event="ALLOWED", result="INFO",
                     message="Whitelisted via dashboard")
    db.add(log)
    db.commit()

    return {"success": True, "message": f"IP {ip} whitelisted"}


# ══════════════════════════════════════════════════════════════
# WEBSOCKET — unchanged, still streams live in-memory state
# ══════════════════════════════════════════════════════════════
class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)
        print(f"[WS] Client connected  — active: {len(self.active)}")

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)
        print(f"[WS] Client disconnected — active: {len(self.active)}")


manager = ConnectionManager()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        await websocket.send_json(state.snapshot())
        while True:
            await asyncio.sleep(2.5)
            await websocket.send_json(state.snapshot())
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        print(f"[WS] Error: {e}")
        manager.disconnect(websocket)