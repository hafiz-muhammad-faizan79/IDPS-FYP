"""
main.py — CyGuardian-X IDPS Backend v2.0
=========================================

ROOT CAUSE OF 403 ON WEBSOCKET:
  Starlette's CORSMiddleware intercepts WebSocket upgrade requests and
  rejects them with 403 if the Origin header doesn't exactly match
  allow_origins. Even with allow_origins=["http://localhost:3000"],
  the browser may send origin as "http://localhost:3000" but Starlette's
  internal check fails for WebSocket upgrades specifically.

FIX:
  Replace CORSMiddleware with a hand-written middleware that:
  1. Adds CORS headers to every HTTP response
  2. Lets WebSocket upgrade requests pass through unconditionally
"""

from fastapi                import FastAPI, Request
from fastapi.responses      import Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types        import ASGIApp
from datetime               import datetime, timedelta
import random

from routers.network        import router as network_router
from routers.configuration  import router as config_router
from routers.audits         import router as audits_router
from routers.incidents      import router as incidents_router
from routers.dashboard      import router as dashboard_router
from routers.auth           import router as auth_router
from routers                import threat_intel
from network_monitor        import start_monitor
from routers.reports        import router as reports_router
from sqladmin               import Admin, ModelView
from database               import engine
from models.user            import User
from models.incident        import Incident
from models.audit           import AuditLog
from models.network         import NetworkLog, BlockedIP
from slowapi                import Limiter, _rate_limit_exceeded_handler
from slowapi.errors         import RateLimitExceeded
from slowapi.util           import get_remote_address


app = FastAPI(title="CyGuardian-X IDPS Backend", version="2.0.0")
admin = Admin(app, engine)
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

class UserAdmin(ModelView, model=User):
    column_list = [User.id, User.username, User.role, User.created_at]

class IncidentAdmin(ModelView, model=Incident):
    column_list = [Incident.id, Incident.severity, Incident.status, Incident.analyst, Incident.updated_at]

class AuditAdmin(ModelView, model=AuditLog):
    column_list = [AuditLog.id, AuditLog.actor, AuditLog.action, AuditLog.created_at]

class NetworkLogAdmin(ModelView, model=NetworkLog):
    column_list = [NetworkLog.id, NetworkLog.src_ip, NetworkLog.event, NetworkLog.result, NetworkLog.created_at]

class BlockedIPAdmin(ModelView, model=BlockedIP):
    column_list = [BlockedIP.id, BlockedIP.ip, BlockedIP.reason, BlockedIP.blocked_by, BlockedIP.created_at]

# ══════════════════════════════════════════════════════════════
# CUSTOM CORS + WEBSOCKET MIDDLEWARE
# Replaces CORSMiddleware entirely — handles both HTTP and WS
# ══════════════════════════════════════════════════════════════
class CORSAndWSMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # WebSocket upgrade — let it pass straight through, no CORS check
        if request.headers.get("upgrade", "").lower() == "websocket":
            return await call_next(request)

        # Handle preflight OPTIONS request
        if request.method == "OPTIONS":
            return Response(
                status_code=200,
                headers={
                    "Access-Control-Allow-Origin":      "*",
                    "Access-Control-Allow-Methods":     "GET, POST, PUT, DELETE, OPTIONS",
                    "Access-Control-Allow-Headers":     "*",
                    "Access-Control-Allow-Credentials": "true",
                },
            )

        # Normal HTTP request — add CORS headers to response
        response = await call_next(request)
        response.headers["Access-Control-Allow-Origin"]      = "*"
        response.headers["Access-Control-Allow-Methods"]     = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"]     = "*"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        return response

app.add_middleware(CORSAndWSMiddleware)

# ── Register routers ────────────────────────────────────────────
app.include_router(network_router)
app.include_router(config_router)
app.include_router(audits_router)
app.include_router(incidents_router)
app.include_router(dashboard_router)
app.include_router(auth_router)
app.include_router(reports_router)
app.include_router(threat_intel.router)

admin.add_view(UserAdmin)
admin.add_view(IncidentAdmin)
admin.add_view(AuditAdmin)
admin.add_view(NetworkLogAdmin)
admin.add_view(BlockedIPAdmin)


# ── Start monitor engine on startup ────────────────────────────
@app.on_event("startup")
async def on_startup():
    start_monitor()
    print("[STARTUP] CyGuardian-X backend ready ✓")


# ════════════════════════════════════════════════════════════════
# ROOT / HEALTH
# ════════════════════════════════════════════════════════════════
@app.get("/")
def root():
    return {"status": "CyGuardian-X backend is running", "version": "2.0.0"}

@app.get("/api/health")
def health():
    return {"status": "online", "timestamp": datetime.now().isoformat()}


# Dashboard endpoints moved to routers/dashboard.py