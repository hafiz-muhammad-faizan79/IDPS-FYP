# idps-backend/models/network.py
from sqlalchemy import Column, String, Integer, Text, DateTime, Boolean
from sqlalchemy.sql import func
from database import Base
from datetime import datetime

class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String, unique=True, index=True, nullable=False)
    reason = Column(String, default="Manual block")
    blocked_by = Column(String, default="system")
    created_at = Column(DateTime, default=datetime.utcnow)

    
class NetworkLog(Base):
    __tablename__ = "network_logs"

    id         = Column(Integer,    primary_key=True, autoincrement=True)
    status     = Column(String(20), nullable=False)   # BLOCKED / ALLOWED / FLAGGED
    src_ip     = Column(String(45), nullable=False)
    event      = Column(String(30), nullable=False)   # BLOCKED / ALLOWED / ALERT
    result     = Column(String(20), nullable=False)   # SUCCESS / INFO / WARNING
    message    = Column(Text,       nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class NetworkAlert(Base):
    __tablename__ = "network_alerts"

    id         = Column(Integer,    primary_key=True, autoincrement=True)
    severity   = Column(String(20), nullable=False)   # Low / Medium / High / Critical
    src_ip     = Column(String(45), nullable=False)
    dst_ip     = Column(String(45), nullable=False)
    message    = Column(Text,       nullable=False)
    protocol   = Column(String(20), nullable=True)
    port       = Column(Integer,    nullable=True)
    resolved   = Column(Boolean,    default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class CapturedPacket(Base):
    __tablename__ = "captured_packets"

    id         = Column(Integer,    primary_key=True, autoincrement=True)
    src_ip     = Column(String(45), nullable=False, index=True)
    dst_ip     = Column(String(45), nullable=False, index=True)
    protocol   = Column(String(20), nullable=False, index=True)
    port       = Column(Integer,    nullable=False, default=0)
    length     = Column(Integer,    nullable=False, default=0)  # bytes
    status     = Column(String(20), nullable=False, default="Established")
    flagged    = Column(Boolean,    default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
