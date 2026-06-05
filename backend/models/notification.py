"""
notification.py — Notifications table
"""
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey
from sqlalchemy.sql import func
from database import Base


class Notification(Base):
    __tablename__ = "notifications"

    id          = Column(Integer,    primary_key=True, autoincrement=True)
    recipient   = Column(String(50), nullable=False, index=True)    # username
    severity    = Column(String(20), nullable=False)                # Critical | High
    title       = Column(String(200), nullable=False)
    message     = Column(Text,        nullable=False)
    src_ip      = Column(String(45),  nullable=True)
    category    = Column(String(50),  nullable=True)                # SIGNATURE_MATCH | AI_ANOMALY | CORRELATION
    correlation_data = Column(Text,   nullable=True)                # JSON of full decision
    email_sent  = Column(Boolean,     default=False)
    read        = Column(Boolean,     default=False, index=True)
    created_at  = Column(DateTime(timezone=True), server_default=func.now(), index=True)
