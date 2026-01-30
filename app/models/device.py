"""
Device Models

Models for trusted devices and device health tracking.
"""

from sqlalchemy import Column, String, Integer, ForeignKey, Float, DateTime, Boolean, Text, Index
from sqlalchemy.orm import relationship
from app.models.base import Base, TimestampMixin


class Device(Base, TimestampMixin):
    """Device model."""
    
    __tablename__ = "devices"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    
    # Device identification
    device_id = Column(String(255), unique=True, nullable=False, index=True)
    device_name = Column(String(255))
    device_type = Column(String(100))  # 'desktop', 'mobile', 'tablet', 'server'
    
    # Device fingerprint
    fingerprint = Column(String(500), nullable=False)
    
    # Trust and health
    trusted = Column(Boolean, default=False, nullable=False)
    health_score = Column(Float, default=0.0, nullable=False)  # 0.0-100.0
    health_data = Column(Text)  # JSON: OS version, security patches, etc.
    
    # Certificate
    certificate_serial = Column(String(255))
    
    # Status
    is_active = Column(Boolean, default=True, nullable=False)
    last_seen = Column(DateTime)
    last_location = Column(String(255))
    
    # Relationships
    user = relationship("User", back_populates="devices")
    
    __table_args__ = (
        Index('idx_devices_user_id', 'user_id'),
        Index('idx_devices_device_id', 'device_id'),
        Index('idx_devices_trusted', 'trusted'),
    )
    
    def __repr__(self):
        return f"<Device(id={self.id}, device_id='{self.device_id}', user_id={self.user_id}, trusted={self.trusted})>"
