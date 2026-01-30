"""
MFA Models

Models for multi-factor authentication secrets.
"""

from sqlalchemy import Column, String, Integer, ForeignKey, Boolean, DateTime, Index
from sqlalchemy.orm import relationship
from app.models.base import Base, TimestampMixin


class MFASecret(Base, TimestampMixin):
    """MFA Secret model."""
    
    __tablename__ = "mfa_secrets"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    
    # MFA Type
    mfa_type = Column(String(50), nullable=False)  # 'totp', 'webauthn', 'sms'
    
    # Secret data (encrypted)
    secret = Column(String(500), nullable=False)
    
    # Metadata
    device_name = Column(String(255))
    is_active = Column(Boolean, default=True, nullable=False)
    last_used = Column(DateTime)
    
    # Backup codes (if applicable)
    backup_codes = Column(String(1000))  # JSON array of hashed backup codes
    
    # Relationships
    user = relationship("User", back_populates="mfa_secrets")
    
    __table_args__ = (
        Index('idx_mfa_secrets_user_id', 'user_id'),
        Index('idx_mfa_secrets_type', 'mfa_type'),
    )
    
    def __repr__(self):
        return f"<MFASecret(id={self.id}, user_id={self.user_id}, type='{self.mfa_type}')>"
