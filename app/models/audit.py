"""
Audit Log Models

Models for security audit logging.
"""

from sqlalchemy import Column, String, Integer, DateTime, Text, Index
from app.models.base import Base


class AuditLog(Base):
    """Audit Log model."""
    
    __tablename__ = "audit_log"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Event identification
    event_type = Column(String(100), nullable=False, index=True)  # 'login', 'logout', 'policy_eval', etc.
    event_category = Column(String(50), nullable=False)  # 'authentication', 'authorization', 'admin'
    
    # Subject
    user_id = Column(Integer)
    username = Column(String(255))
    
    # Event details
    action = Column(String(100), nullable=False)
    resource = Column(String(500))
    result = Column(String(50), nullable=False)  # 'success', 'failure', 'denied'
    
    # Context
    ip_address = Column(String(45))
    user_agent = Column(String(500))
    session_id = Column(String(255))
    device_id = Column(String(255))
    
    # Details (JSON)
    details = Column(Text)  # Additional event-specific data as JSON
    
    # Timestamp
    timestamp = Column(DateTime, nullable=False, index=True)
    
    __table_args__ = (
        Index('idx_audit_log_event_type', 'event_type'),
        Index('idx_audit_log_user_id', 'user_id'),
        Index('idx_audit_log_timestamp', 'timestamp'),
        Index('idx_audit_log_result', 'result'),
    )
    
    def __repr__(self):
        return f"<AuditLog(id={self.id}, event_type='{self.event_type}', user='{self.username}', result='{self.result}')>"
