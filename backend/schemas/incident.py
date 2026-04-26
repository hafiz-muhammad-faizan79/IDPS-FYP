# idps-backend/schemas/incident.py
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

# ── Incidents ──────────────────────────────────────────
class IncidentOut(BaseModel):
    id:         str
    desc:       str
    type:       str
    severity:   str
    status:     str
    analyst:    str
    src_ip:     str
    dst_ip:     str
    protocol:   str
    port:       int
    timestamp:  str
    updated_at: datetime
    created_at: datetime
    class Config:
        from_attributes = True

class IncidentAssign(BaseModel):
    analyst: str
    notes:   Optional[str] = None

class IncidentResolveAll(BaseModel):
    ids: List[str]

# ── Detections ─────────────────────────────────────────
class DetectionOut(BaseModel):
    id:             int
    timestamp:      str
    src_ip:         str
    dst_ip:         str
    protocol:       str
    port:           int
    det_type:       str
    severity:       str
    classification: str
    explanation:    str
    created_at:     datetime
    class Config:
        from_attributes = True

# ── Timeline ───────────────────────────────────────────
class TimelineEventOut(BaseModel):
    time:  str
    event: str
    class Config:
        from_attributes = True

# ── IP Action ──────────────────────────────────────────
class IPActionRequest(BaseModel):
    ip:          str
    actioned_by: Optional[str] = "analyst"