"""
routers/network.py — DB-backed persistent logs + alerts, live WebSocket unchanged
"""
import asyncio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, Depends ,Request
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime
from auth import require_role
from models.user import User
from database import get_db
from auth import get_current_user
from models.network import NetworkLog, NetworkAlert
from models.network import BlockedIP
from network_monitor import state, MY_IP
from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address

router = APIRouter(prefix="/api/network", tags=["Network Monitoring"])
limiter = Limiter(key_func=get_remote_address)

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
def block_ip(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "soc_lead")),
):
    ip = payload.get("ip", "unknown")

    # Persist to DB
    existing = db.query(BlockedIP).filter(BlockedIP.ip == ip).first()
    if not existing:
        db.add(
            BlockedIP(
                ip=ip,
                reason="Blocked via network monitor",
                blocked_by=current_user.username,  # <- use real actor
            )
        )
        db.commit()

    # Also log the action
    log = NetworkLog(
        status="BLOCKED",
        src_ip=ip,
        event="BLOCKED",
        result="SUCCESS",
        message=f"Manually blocked via dashboard by {current_user.username}",
    )
    db.add(log)
    db.commit()

    # Update in-memory state
    with state.lock:
        state.threats_blocked += 1
        for c in state.connections:
            if c["srcIp"] == ip:
                c["status"] = "Blocked"
                c["flagged"] = True

    return {
        "success": True,
        "message": f"IP {ip} blocked",
        "by": current_user.username,
    }


@router.post("/whitelist-ip")
def whitelist_ip(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "soc_lead")),
):
    ip = payload.get("ip", "unknown")

    # Optional: remove from blocked list if present
    existing = db.query(BlockedIP).filter(BlockedIP.ip == ip).first()
    if existing:
        db.delete(existing)
        db.commit()

    # Log the action
    log = NetworkLog(
        status="ALLOWED",
        src_ip=ip,
        event="ALLOWED",
        result="INFO",
        message=f"Whitelisted via dashboard by {current_user.username}",
    )
    db.add(log)
    db.commit()

    return {
        "success": True,
        "message": f"IP {ip} whitelisted",
        "by": current_user.username,
    }

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

# ══════════════════════════════════════════════════════════════
# PACKET HISTORY — query stored packets from PostgreSQL
# ══════════════════════════════════════════════════════════════
@router.get("/packets")
def get_packets(
    src_ip:   Optional[str] = Query(None),
    dst_ip:   Optional[str] = Query(None),
    protocol: Optional[str] = Query(None),
    port:     Optional[int] = Query(None),
    flagged:  Optional[bool]= Query(None),
    limit:    int           = Query(100),
    db: Session = Depends(get_db),
):
    from models.network import CapturedPacket
    q = db.query(CapturedPacket).order_by(CapturedPacket.created_at.desc())
    if src_ip:    q = q.filter(CapturedPacket.src_ip.ilike(f"%{src_ip}%"))
    if dst_ip:    q = q.filter(CapturedPacket.dst_ip.ilike(f"%{dst_ip}%"))
    if protocol:  q = q.filter(CapturedPacket.protocol == protocol.upper())
    if port:      q = q.filter(CapturedPacket.port == port)
    if flagged is not None: q = q.filter(CapturedPacket.flagged == flagged)
    rows = q.limit(limit).all()
    return {
        "total": len(rows),
        "packets": [
            {
                "id":        r.id,
                "src_ip":    r.src_ip,
                "dst_ip":    r.dst_ip,
                "protocol":  r.protocol,
                "port":      r.port,
                "length":    r.length,
                "status":    r.status,
                "flagged":   r.flagged,
                "timestamp": r.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            }
            for r in rows
        ]
    }


@router.get("/packets/stats")
def get_packet_stats(db: Session = Depends(get_db)):
    from models.network import CapturedPacket
    from sqlalchemy import func as sqlfunc

    total     = db.query(CapturedPacket).count()
    flagged   = db.query(CapturedPacket).filter(CapturedPacket.flagged == True).count()

    # Top 5 source IPs
    top_src = db.query(
        CapturedPacket.src_ip,
        sqlfunc.count(CapturedPacket.id).label("count")
    ).group_by(CapturedPacket.src_ip)\
     .order_by(sqlfunc.count(CapturedPacket.id).desc())\
     .limit(5).all()

    # Protocol breakdown
    proto_rows = db.query(
        CapturedPacket.protocol,
        sqlfunc.count(CapturedPacket.id).label("count")
    ).group_by(CapturedPacket.protocol)\
     .order_by(sqlfunc.count(CapturedPacket.id).desc())\
     .all()

    # Top ports
    top_ports = db.query(
        CapturedPacket.port,
        sqlfunc.count(CapturedPacket.id).label("count")
    ).group_by(CapturedPacket.port)\
     .order_by(sqlfunc.count(CapturedPacket.id).desc())\
     .limit(5).all()

    return {
        "total_stored":   total,
        "flagged":        flagged,
        "top_sources":    [{"ip": r[0], "count": r[1]} for r in top_src],
        "protocols":      [{"protocol": r[0], "count": r[1]} for r in proto_rows],
        "top_ports":      [{"port": r[0], "count": r[1]} for r in top_ports],
    }


# ══════════════════════════════════════════════════════════════
# SERVICE CONTROLS — restart engines, switch interface
# ══════════════════════════════════════════════════════════════
import subprocess
import psutil as _psutil

# Track service states
_service_states = {
    "ids_engine":       {"running": True,  "label": "IDS Engine"},
    "packet_inspector": {"running": True,  "label": "Packet Inspector"},
    "firewall":         {"running": False, "label": "Firewall"},
    "network_adapter":  {"running": True,  "label": "Network Adapter"},
}


@router.get("/services")
def get_services(db: Session = Depends(get_db)):
    """Return real service states + system info."""
    import psutil as ps
    services = []
    for key, svc in _service_states.items():
        services.append({
            "key":     key,
            "name":    svc["label"],
            "running": svc["running"],
            "status":  "ACTIVE" if svc["running"] else "STOPPED",
            "ok":      svc["running"],
        })
    return {
        "services": services,
        "interfaces": _get_interfaces(),
        "current_interface": state.lock and INTERFACE,
    }


def _get_interfaces():
    """Return all available network interfaces with stats."""
    import psutil as ps
    ifaces = []
    stats = ps.net_if_stats()
    addrs = ps.net_if_addrs()
    io    = ps.net_io_counters(pernic=True)

    for name, stat in stats.items():
        if name == "lo":
            continue
        ip = None
        for addr in addrs.get(name, []):
            if addr.family.name == "AF_INET":
                ip = addr.address
                break
        nic_io = io.get(name)
        ifaces.append({
            "name":    name,
            "up":      stat.isup,
            "speed":   stat.speed,
            "ip":      ip or "N/A",
            "bytes_sent": nic_io.bytes_sent if nic_io else 0,
            "bytes_recv": nic_io.bytes_recv if nic_io else 0,
        })
    return ifaces


@router.post("/services/{service_key}/restart")
def restart_service(
    service_key: str,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Restart a service — admin/soc_lead only."""
    if current_user.role not in ("admin", "soc_lead"):
        raise HTTPException(403, "Admin or SOC Lead required")

    if service_key not in _service_states:
        raise HTTPException(404, f"Service {service_key} not found")

    svc = _service_states[service_key]

    # Simulate restart — mark as stopped then running
    svc["running"] = False

    # For IDS engine — actually restart the monitor thread
    if service_key == "ids_engine":
        try:
            from network_monitor import start_monitor
            import threading
            t = threading.Thread(target=start_monitor, daemon=True)
            t.start()
        except Exception as e:
            print(f"[RESTART] IDS engine restart error: {e}")

    # Mark back as running after 2 seconds
    import time
    time.sleep(1)
    svc["running"] = True

    # Log the action
    log = NetworkLog(
        status="INFO",
        src_ip=current_user.username,
        event="SERVICE_RESTART",
        result="SUCCESS",
        message=f"{svc['label']} restarted by {current_user.username}",
    )
    db.add(log)
    db.commit()

    return {
        "success": True,
        "message": f"{svc['label']} restarted successfully",
        "service": {
            "key":     service_key,
            "name":    svc["label"],
            "running": svc["running"],
            "status":  "ACTIVE",
        }
    }


@router.post("/services/{service_key}/toggle")
def toggle_service(
    service_key: str,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Toggle a service on/off — admin only."""
    if current_user.role != "admin":
        raise HTTPException(403, "Admin only")

    if service_key not in _service_states:
        raise HTTPException(404, f"Service {service_key} not found")

    svc = _service_states[service_key]
    svc["running"] = not svc["running"]

    log = NetworkLog(
        status="INFO",
        src_ip=current_user.username,
        event="SERVICE_TOGGLE",
        result="SUCCESS",
        message=f"{svc['label']} {'started' if svc['running'] else 'stopped'} by {current_user.username}",
    )
    db.add(log)
    db.commit()

    return {
        "success": True,
        "running": svc["running"],
        "message": f"{svc['label']} {'started' if svc['running'] else 'stopped'}",
    }


@router.post("/switch-interface")
def switch_interface(
    body: dict,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Switch capture interface — admin only."""
    if current_user.role != "admin":
        raise HTTPException(403, "Admin only")

    new_iface = body.get("interface", "")
    if not new_iface:
        raise HTTPException(400, "interface is required")

    import network_monitor as nm
    old_iface = nm.INTERFACE
    nm.INTERFACE = new_iface
    nm.MY_IP = body.get("ip", nm.MY_IP)

    log = NetworkLog(
        status="INFO",
        src_ip=current_user.username,
        event="INTERFACE_SWITCH",
        result="SUCCESS",
        message=f"Capture interface changed from {old_iface} to {new_iface} by {current_user.username}",
    )
    db.add(log)
    db.commit()

    return {
        "success": True,
        "message": f"Switched from {old_iface} to {new_iface}",
        "interface": new_iface,
    }
