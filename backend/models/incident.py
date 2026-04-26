from sqlalchemy import Column, String, Integer, Text, DateTime
from sqlalchemy.sql import func
from database import Base


class Incident(Base):
    __tablename__ = "incidents"

    id         = Column(String(20),  primary_key=True)
    desc       = Column(Text,        nullable=False)
    type       = Column(String(50),  nullable=False)
    severity   = Column(String(20),  nullable=False)
    status     = Column(String(20),  nullable=False, default="Open")
    analyst    = Column(String(100), nullable=False, default="analyst1")
    src_ip     = Column(String(45),  nullable=False)
    dst_ip     = Column(String(45),  nullable=False)
    protocol   = Column(String(20),  nullable=False)
    port       = Column(Integer,     nullable=False, default=0)
    timestamp  = Column(String(20),  nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Detection(Base):
    __tablename__ = "detections"

    id             = Column(Integer,     primary_key=True, autoincrement=True)
    timestamp      = Column(String(20),  nullable=False)
    src_ip         = Column(String(45),  nullable=False)
    dst_ip         = Column(String(45),  nullable=False)
    protocol       = Column(String(20),  nullable=False)
    port           = Column(Integer,     nullable=False, default=0)
    det_type       = Column(String(20),  nullable=False)
    severity       = Column(String(20),  nullable=False)
    classification = Column(String(20),  nullable=False)
    explanation    = Column(Text,        nullable=False)
    created_at     = Column(DateTime(timezone=True), server_default=func.now())


class IncidentTimeline(Base):
    __tablename__ = "incident_timeline"

    id          = Column(Integer,    primary_key=True, autoincrement=True)
    incident_id = Column(String(20), nullable=False, index=True)
    time        = Column(String(10), nullable=False)
    event       = Column(Text,       nullable=False)
    created_at  = Column(DateTime(timezone=True), server_default=func.now())


class DetectionIPAction(Base):
    __tablename__ = "detection_ip_actions"

    ip          = Column(String(45),  primary_key=True)
    action      = Column(String(20),  nullable=False)
    actioned_by = Column(String(100), default="analyst")
    actioned_at = Column(DateTime(timezone=True), server_default=func.now())
