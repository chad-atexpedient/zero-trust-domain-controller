"""
OAuth Models

Models for OAuth2/OIDC clients and tokens.
"""

from sqlalchemy import Column, String, Integer, Text, Boolean, DateTime, Index
from app.models.base import Base, TimestampMixin


class OAuthClient(Base, TimestampMixin):
    """OAuth2/OIDC Client model."""
    
    __tablename__ = "oauth_clients"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Client identification
    client_id = Column(String(255), unique=True, nullable=False, index=True)
    client_secret_hash = Column(String(255), nullable=False)
    client_name = Column(String(255), nullable=False)
    
    # Client metadata
    client_type = Column(String(50), nullable=False)  # 'confidential', 'public'
    grant_types = Column(Text, nullable=False)  # JSON array: ['authorization_code', 'refresh_token']
    response_types = Column(Text, nullable=False)  # JSON array: ['code', 'token']
    
    # Redirect URIs
    redirect_uris = Column(Text, nullable=False)  # JSON array
    
    # Scopes
    allowed_scopes = Column(Text, nullable=False)  # JSON array: ['openid', 'profile', 'email']
    
    # OIDC specific
    token_endpoint_auth_method = Column(String(50), default='client_secret_basic')
    
    # Status
    is_active = Column(Boolean, default=True, nullable=False)
    
    # Owner
    owner_id = Column(Integer)  # User ID of the client owner
    
    __table_args__ = (
        Index('idx_oauth_clients_client_id', 'client_id'),
        Index('idx_oauth_clients_active', 'is_active'),
    )
    
    def __repr__(self):
        return f"<OAuthClient(id={self.id}, client_id='{self.client_id}', name='{self.client_name}')>"
