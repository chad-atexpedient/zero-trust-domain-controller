"""
Certificate Models

Models for tracking issued certificates.
"""

from sqlalchemy import Column, String, Integer, DateTime, Text, Boolean, Index
from app.models.base import Base, TimestampMixin


class Certificate(Base, TimestampMixin):
    """Certificate model."""
    
    __tablename__ = "certificates"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Certificate identification
    serial_number = Column(String(255), unique=True, nullable=False, index=True)
    common_name = Column(String(255), nullable=False)
    certificate_type = Column(String(50), nullable=False)  # 'server', 'client', 'device'
    
    # Subject
    subject_dn = Column(String(500), nullable=False)
    subject_alt_names = Column(Text)  # JSON array
    
    # Issuer
    issuer_dn = Column(String(500), nullable=False)
    
    # Validity
    not_before = Column(DateTime, nullable=False)
    not_after = Column(DateTime, nullable=False, index=True)
    
    # Certificate data
    certificate_pem = Column(Text, nullable=False)
    public_key_pem = Column(Text, nullable=False)
    
    # Status
    revoked = Column(Boolean, default=False, nullable=False)
    revoked_at = Column(DateTime)
    revocation_reason = Column(String(255))
    
    # Ownership
    user_id = Column(Integer)  # If issued to a user
    device_id = Column(String(255))  # If issued to a device
    
    __table_args__ = (
        Index('idx_certificates_serial', 'serial_number'),
        Index('idx_certificates_not_after', 'not_after'),
        Index('idx_certificates_revoked', 'revoked'),
        Index('idx_certificates_type', 'certificate_type'),
    )
    
    def __repr__(self):
        return f"<Certificate(id={self.id}, serial='{self.serial_number}', cn='{self.common_name}', type='{self.certificate_type}')>"
