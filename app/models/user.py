"""
User Models

Models for users, groups, and user-group relationships.
"""

from sqlalchemy import Column, String, Boolean, Integer, DateTime, ForeignKey, Text, Index
from sqlalchemy.orm import relationship
from app.models.base import Base, TimestampMixin


class User(Base, TimestampMixin):
    """User model."""
    
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(255), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    
    # Profile
    first_name = Column(String(255))
    last_name = Column(String(255))
    display_name = Column(String(255))
    
    # Security
    mfa_required = Column(Boolean, default=False, nullable=False)
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    account_locked = Column(Boolean, default=False, nullable=False)
    locked_until = Column(DateTime)
    failed_attempts = Column(Integer, default=0, nullable=False)
    password_changed_at = Column(DateTime)
    
    # Status
    enabled = Column(Boolean, default=True, nullable=False)
    email_verified = Column(Boolean, default=False, nullable=False)
    last_login = Column(DateTime)
    
    # Attributes (JSON stored as text for simplicity)
    attributes = Column(Text)  # Store as JSON string
    
    # Relationships
    mfa_secrets = relationship("MFASecret", back_populates="user", cascade="all, delete-orphan")
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    devices = relationship("Device", back_populates="user", cascade="all, delete-orphan")
    user_groups = relationship("UserGroup", back_populates="user", cascade="all, delete-orphan")
    
    __table_args__ = (
        Index('idx_users_username', 'username'),
        Index('idx_users_email', 'email'),
        Index('idx_users_enabled', 'enabled'),
    )
    
    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', email='{self.email}')>"


class Group(Base, TimestampMixin):
    """Group model."""
    
    __tablename__ = "groups"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), unique=True, nullable=False, index=True)
    description = Column(Text)
    
    # Attributes
    attributes = Column(Text)  # Store as JSON string
    
    # Relationships
    user_groups = relationship("UserGroup", back_populates="group", cascade="all, delete-orphan")
    
    __table_args__ = (
        Index('idx_groups_name', 'name'),
    )
    
    def __repr__(self):
        return f"<Group(id={self.id}, name='{self.name}')>"


class UserGroup(Base, TimestampMixin):
    """User-Group membership model."""
    
    __tablename__ = "user_groups"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    group_id = Column(Integer, ForeignKey('groups.id', ondelete='CASCADE'), nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="user_groups")
    group = relationship("Group", back_populates="user_groups")
    
    __table_args__ = (
        Index('idx_user_groups_user_id', 'user_id'),
        Index('idx_user_groups_group_id', 'group_id'),
    )
    
    def __repr__(self):
        return f"<UserGroup(user_id={self.user_id}, group_id={self.group_id})>"
