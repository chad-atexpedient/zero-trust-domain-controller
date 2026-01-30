"""
Policy Models

Models for ABAC policies.
"""

from sqlalchemy import Column, String, Integer, Text, Boolean, Index
from app.models.base import Base, TimestampMixin


class Policy(Base, TimestampMixin):
    """Policy model for ABAC."""
    
    __tablename__ = "policies"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), unique=True, nullable=False, index=True)
    description = Column(Text)
    
    # Policy effect
    effect = Column(String(10), nullable=False)  # 'allow' or 'deny'
    
    # Policy components (stored as JSON)
    principals = Column(Text, nullable=False)  # JSON array: ["user:john", "group:admins"]
    resources = Column(Text, nullable=False)   # JSON array: ["service:db:*", "api:/admin/*"]
    actions = Column(Text, nullable=False)     # JSON array: ["read", "write", "delete"]
    conditions = Column(Text)                  # JSON object: {"ip_range": "10.0.0.0/8", ...}
    
    # Priority and status
    priority = Column(Integer, default=100, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    
    __table_args__ = (
        Index('idx_policies_name', 'name'),
        Index('idx_policies_enabled', 'enabled'),
        Index('idx_policies_priority', 'priority'),
    )
    
    def __repr__(self):
        return f"<Policy(id={self.id}, name='{self.name}', effect='{self.effect}', enabled={self.enabled})>"
