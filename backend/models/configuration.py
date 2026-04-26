# idps-backend/models/configuration.py
from sqlalchemy import Column, String, Integer, Boolean, Float, Text, DateTime, Enum as SAEnum
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func
from database import Base
import enum

# ── Enums ─────────────────────────────────────────────
class SeverityEnum(str, enum.Enum):
    low      = "Low"
    medium   = "Medium"
    high     = "High"
    critical = "Critical"

class ActionEnum(str, enum.Enum):
    alert = "Alert"
    drop  = "Drop"
    block = "Block"
    log   = "Log"

class RiskLevelEnum(str, enum.Enum):
    low      = "Low"
    medium   = "Medium"
    high     = "High"
    critical = "Critical"

# ── Signature Rules ────────────────────────────────────
class SignatureRule(Base):
    __tablename__ = "sig_rules"

    id         = Column(String(20),  primary_key=True)   # e.g. "SIG-001"
    name       = Column(String(200), nullable=False)
    category   = Column(String(100), nullable=False)
    severity   = Column(SAEnum(SeverityEnum), nullable=False)
    protocol   = Column(String(20),  nullable=False)
    action     = Column(SAEnum(ActionEnum),   nullable=False)
    pattern    = Column(Text,        nullable=False)
    enabled    = Column(Boolean,     default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

# ── Ransomware Rules ───────────────────────────────────
class RansomwareRule(Base):
    __tablename__ = "ransom_rules"

    id              = Column(String(20),  primary_key=True)  # e.g. "RAN-001"
    name            = Column(String(200), nullable=False)
    risk_level      = Column(SAEnum(RiskLevelEnum), nullable=False)
    pattern         = Column(Text,        nullable=False)
    enabled         = Column(Boolean,     default=True)
    last_triggered  = Column(String(50),  nullable=True)
    created_at      = Column(DateTime(timezone=True), server_default=func.now())
    updated_at      = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

# ── Anomaly Detection Config (single-row) ─────────────
class AnomalyConfig(Base):
    __tablename__ = "anomaly_config"

    id                  = Column(Integer, primary_key=True, default=1)
    enabled             = Column(Boolean, default=True)
    sensitivity         = Column(String(20),  default="Medium")   # Low / Medium / High
    baseline_window     = Column(Integer,     default=300)         # seconds
    packet_size_mult    = Column(Float,       default=3.0)
    conn_rate_mult      = Column(Float,       default=5.0)
    dns_query_rate      = Column(Integer,     default=100)
    traffic_volume_mult = Column(Float,       default=10.0)
    alert_cooldown      = Column(Integer,     default=60)          # seconds
    updated_at          = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

# ── Network Interfaces ─────────────────────────────────
class NetworkInterface(Base):
    __tablename__ = "network_interfaces"

    id         = Column(Integer,     primary_key=True, autoincrement=True)
    name       = Column(String(50),  nullable=False, unique=True)  # eth0, eth1 …
    mode       = Column(String(20),  default="Monitor")             # Monitor / Inline
    enabled    = Column(Boolean,     default=True)
    speed      = Column(String(20),  nullable=True)                 # "1 Gbps"
    ip_address = Column(String(45),  nullable=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())



# ── Alert Notification Settings ────────────────────────
class AlertSettings(Base):
    __tablename__ = "alert_settings"

    id                  = Column(Integer, primary_key=True, default=1)
    email_enabled       = Column(Boolean, default=True)
    email_recipients    = Column(JSONB,   default=list)   # ["soc@org.com", ...]
    sms_enabled         = Column(Boolean, default=False)
    sms_numbers         = Column(JSONB,   default=list)
    webhook_enabled     = Column(Boolean, default=False)
    webhook_url         = Column(Text,    nullable=True)
    min_severity        = Column(String(20), default="High")
    updated_at          = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

# ── System / Performance Settings ─────────────────────
class SystemSettings(Base):
    __tablename__ = "system_settings"

    id                  = Column(Integer, primary_key=True, default=1)
    log_retention_days  = Column(Integer, default=90)
    max_packet_capture  = Column(Integer, default=10000)
    performance_mode    = Column(String(20), default="Balanced")   # Minimal / Balanced / Max
    auto_block_enabled  = Column(Boolean, default=False)
    auto_block_threshold= Column(Integer, default=100)             # events before auto-block
    updated_at          = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())