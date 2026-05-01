from sqlalchemy import Column, String, Integer, DateTime, Boolean, Float, Text, Index
from sqlalchemy.sql import func
from gateway.db.database import Base
from datetime import datetime

class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        Index('idx_user_email', 'email', unique=True),
        Index('idx_user_active', 'is_active'),
    )
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(50), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=True)
    full_name = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True, index=True)
    is_superuser = Column(Boolean, default=False)
    role = Column(String(50), default="user")
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_login = Column(DateTime(timezone=True), nullable=True)
    
    def __repr__(self):
        return f"<User {self.email}>"

class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index('idx_audit_user', 'user_id'),
        Index('idx_audit_timestamp', 'timestamp'),
    )
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True, index=True)
    action = Column(String(100), nullable=False, index=True)
    resource = Column(String(255), nullable=True)
    method = Column(String(10), nullable=False)
    status_code = Column(Integer, nullable=True)
    event_type = Column(String(30), nullable=True, index=True)  # successful|unsuccessful|blocked|rate_limited|proxied
    ip_address = Column(String(45), index=True)
    user_agent = Column(String(500), nullable=True)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)

class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        Index('idx_security_type', 'threat_type'),
        Index('idx_security_timestamp', 'timestamp'),
        Index('idx_security_ip', 'ip_address'),
    )
    
    id = Column(Integer, primary_key=True, index=True)
    threat_type = Column(String(50), nullable=False, index=True)
    ip_address = Column(String(45), nullable=False, index=True)
    endpoint = Column(String(500), nullable=True)
    payload = Column(Text, nullable=True)
    risk_score = Column(Float, default=0.0)
    status = Column(String(20), default="detected")
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)


class PasswordReset(Base):
    __tablename__ = "password_resets"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), index=True, nullable=False)
    token = Column(String(255), unique=True, index=True, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
