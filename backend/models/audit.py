# idps-backend/models/audit.py
from sqlalchemy import Column, String, Integer, Boolean, Text, DateTime
from sqlalchemy.sql import func
from database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id          = Column(String(20),  primary_key=True)   # AUD-001
    timestamp   = Column(String(20),  nullable=False)
    actor       = Column(String(100), nullable=False)
    change_type = Column(String(50),  nullable=False)
    target      = Column(String(200), nullable=False)
    action      = Column(String(200), nullable=False)
    details     = Column(Text,        nullable=False)
    rolled_back = Column(Boolean,     default=False)
    created_at  = Column(DateTime(timezone=True), server_default=func.now())


class MaliciousIP(Base):
    __tablename__ = "malicious_ips"

    ip       = Column(String(45),  primary_key=True)
    events   = Column(Integer,     default=0)
    type     = Column(String(50),  nullable=False)
    avg_sev  = Column(String(20),  nullable=False)
    protocol = Column(String(20),  nullable=False)
    country  = Column(String(100), nullable=False)
    last_seen= Column(String(20),  nullable=False)