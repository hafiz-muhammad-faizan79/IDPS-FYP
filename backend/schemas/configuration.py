# idps-backend/schemas/configuration.py
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

# ── Signature Rules ────────────────────────────────────
class SignatureRuleBase(BaseModel):
    name:     str
    category: str
    severity: str
    protocol: str
    action:   str
    pattern:  str
    enabled:  bool = True

class SignatureRuleCreate(SignatureRuleBase):
    id: str  # caller provides e.g. "SIG-042"

class SignatureRuleUpdate(BaseModel):
    name:     Optional[str]  = None
    category: Optional[str]  = None
    severity: Optional[str]  = None
    protocol: Optional[str]  = None
    action:   Optional[str]  = None
    pattern:  Optional[str]  = None
    enabled:  Optional[bool] = None

class SignatureRuleOut(SignatureRuleBase):
    id:         str
    created_at: datetime
    updated_at: datetime
    class Config:
        from_attributes = True

# ── Ransomware Rules ───────────────────────────────────
class RansomwareRuleBase(BaseModel):
    name:           str
    risk_level:     str
    pattern:        str
    enabled:        bool = True
    last_triggered: Optional[str] = None

class RansomwareRuleCreate(RansomwareRuleBase):
    id: str

class RansomwareRuleUpdate(BaseModel):
    name:           Optional[str]  = None
    risk_level:     Optional[str]  = None
    pattern:        Optional[str]  = None
    enabled:        Optional[bool] = None
    last_triggered: Optional[str]  = None

class RansomwareRuleOut(RansomwareRuleBase):
    id:         str
    created_at: datetime
    updated_at: datetime
    class Config:
        from_attributes = True

# ── Anomaly Config ─────────────────────────────────────
class AnomalyConfigUpdate(BaseModel):
    enabled:             Optional[bool]  = None
    sensitivity:         Optional[str]   = None
    baseline_window:     Optional[int]   = None
    packet_size_mult:    Optional[float] = None
    conn_rate_mult:      Optional[float] = None
    dns_query_rate:      Optional[int]   = None
    traffic_volume_mult: Optional[float] = None
    alert_cooldown:      Optional[int]   = None

class AnomalyConfigOut(AnomalyConfigUpdate):
    id:         int
    updated_at: datetime
    class Config:
        from_attributes = True

# ── Network Interface ──────────────────────────────────
class NetworkInterfaceUpdate(BaseModel):
    mode:       Optional[str]  = None
    enabled:    Optional[bool] = None
    ip_address: Optional[str]  = None

class NetworkInterfaceOut(BaseModel):
    id:         int
    name:       str
    mode:       str
    enabled:    bool
    speed:      Optional[str]
    ip_address: Optional[str]
    updated_at: datetime
    class Config:
        from_attributes = True

# ── Alert Settings ─────────────────────────────────────
class AlertSettingsUpdate(BaseModel):
    email_enabled:    Optional[bool]      = None
    email_recipients: Optional[List[str]] = None
    sms_enabled:      Optional[bool]      = None
    sms_numbers:      Optional[List[str]] = None
    webhook_enabled:  Optional[bool]      = None
    webhook_url:      Optional[str]       = None
    min_severity:     Optional[str]       = None

class AlertSettingsOut(AlertSettingsUpdate):
    id:         int
    updated_at: datetime
    class Config:
        from_attributes = True

# ── System Settings ────────────────────────────────────
class SystemSettingsUpdate(BaseModel):
    log_retention_days:   Optional[int]  = None
    max_packet_capture:   Optional[int]  = None
    performance_mode:     Optional[str]  = None
    auto_block_enabled:   Optional[bool] = None
    auto_block_threshold: Optional[int]  = None

class SystemSettingsOut(SystemSettingsUpdate):
    id:         int
    updated_at: datetime
    class Config:
        from_attributes = True