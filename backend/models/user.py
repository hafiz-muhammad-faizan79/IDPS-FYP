# idps-backend/models/user.py
from sqlalchemy import Column, String, Boolean, DateTime
from sqlalchemy.sql import func
from database import Base


class User(Base):
    __tablename__ = "users"

    id         = Column(String(20),  primary_key=True)   # USR-001
    name       = Column(String(100), nullable=False)
    email      = Column(String(200), nullable=False, unique=True)
    username   = Column(String(50),  nullable=False, unique=True)
    password   = Column(String(200), nullable=False)     # bcrypt hash
    role       = Column(String(50),  nullable=False, default="analyst")
    avatar     = Column(String(5),   nullable=True)      # initials e.g. "AR"
    is_active  = Column(Boolean,     default=True)
    last_login = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())