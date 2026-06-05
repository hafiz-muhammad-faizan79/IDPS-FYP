"""
agent.py — Agent system data models
=====================================
Two tables underpin the multi-agent architecture:

  • agent_events   — the message bus. Any agent can publish, any agent
                     subscribes by polling. Includes correlation source data.

  • agent_actions  — recommended / approved / executed actions.
                     The approval workflow lives here.
"""

from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey
from sqlalchemy.sql import func
from database import Base


class AgentEvent(Base):
    """Message bus row — every agent communicates via this."""
    __tablename__ = "agent_events"

    id            = Column(Integer,    primary_key=True, autoincrement=True)
    event_type    = Column(String(50), nullable=False, index=True)    # THREAT_DETECTED | TRIAGE_COMPLETE | etc.
    source_agent  = Column(String(50), nullable=False, index=True)    # which agent published
    src_ip        = Column(String(45), nullable=True, index=True)
    severity      = Column(String(20), nullable=True)                 # Critical | High | Medium | Low | Info
    category      = Column(String(50), nullable=True)                 # SIGNATURE_MATCH | AI_ANOMALY | CORRELATION
    payload       = Column(Text,        nullable=False)               # JSON: full event details
    processed_by  = Column(Text,        nullable=True)                # JSON list: which agents have consumed it
    created_at    = Column(DateTime(timezone=True), server_default=func.now(), index=True)


class AgentAction(Base):
    """Recommended / executed action with approval state."""
    __tablename__ = "agent_actions"

    id             = Column(Integer,    primary_key=True, autoincrement=True)
    agent_name     = Column(String(50), nullable=False, index=True)
    action_type    = Column(String(50), nullable=False)              # BLOCK_IP | ISOLATE | RATE_LIMIT | NOTIFY
    target         = Column(String(100), nullable=False)             # src_ip / username / etc.
    severity       = Column(String(20), nullable=False)
    confidence     = Column(Integer,    nullable=False)              # 0-100
    autonomy_level = Column(String(20), nullable=False)              # AUTO | APPROVAL_REQUIRED | RECOMMEND_ONLY
    status         = Column(String(20), nullable=False, default="PENDING", index=True)
                                                                     # PENDING | APPROVED | REJECTED | EXECUTED | FAILED
    reasoning      = Column(Text,       nullable=True)               # LLM-generated explanation
    raw_decision   = Column(Text,       nullable=True)               # JSON: full correlation decision
    approved_by    = Column(String(50), nullable=True)               # admin username
    approved_at    = Column(DateTime(timezone=True), nullable=True)
    executed_at    = Column(DateTime(timezone=True), nullable=True)
    error_message  = Column(Text,       nullable=True)
    created_at     = Column(DateTime(timezone=True), server_default=func.now(), index=True)
