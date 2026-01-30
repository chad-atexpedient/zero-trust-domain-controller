"""
Session Models

Models for user sessions and authentication state.
"""

from sqlalchemy import Column, String, Integer, ForeignKey, Float, DateTime, Boolean, Text, Index
from sqlalchemy.orm import relationship
from app.models.base import Base, TimestampMixin


class Session(Base, TimestampMixin):
    """Session model."""
    
    __tablename__ = "sessions"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(255), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    
    # Session metadata
    ip_address = Column(String(45))  # IPv6-compatible
    user_agent = Column(String(500))
    device_id = Column(String(255))
    
    # Security
    risk_score = Column(Float, default=0.0, nullable=False)
    mfa_verified = Column(Boolean, default=False, nullable=False)
    device_trusted = Column(Boolean, default=False, nullable=False)
    
    # Tokens
    access_token = Column(Text)
    refresh_token = Column(Text)
    
    # Validity
    expires_at = Column(DateTime, nullable=False)
    last_activity = Column(DateTime)
    is_active = Column(Boolean, default=True, nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="sessions")
    
    __table_args__ = (
        Index('idx_sessions_session_id', 'session_id'),
        Index('idx_sessions_user_id', 'user_id'),
        Index('idx_sessions_expires_at', 'expires_at'),
        Index('idx_sessions_active', 'is_active'),
    )
    
    def __repr__(self):
        return f"<Session(id={self.id}, session_id='{self.session_id}', user_id={self.user_id}, active={self.is_active})>"
