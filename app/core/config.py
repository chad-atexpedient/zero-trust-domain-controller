"""Application configuration management."""

import secrets
from functools import lru_cache
from typing import List, Optional

from pydantic import Field, PostgresDsn, RedisDsn, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )
    
    # Application
    DEBUG: bool = False
    HOST: str = "0.0.0.0"
    PORT: int = 8443
    WORKERS: int = 4
    LOG_LEVEL: str = "INFO"
    JSON_LOGS: bool = True
    
    # Domain Configuration
    DOMAIN_NAME: str = "example.com"
    DOMAIN_REALM: str = "EXAMPLE.COM"
    BASE_DN: str = "dc=example,dc=com"
    ORGANIZATION: str = "Example Organization"
    
    # Database
    DATABASE_URL: PostgresDsn = Field(
        default="postgresql://ztdc:changeme123@localhost:5432/ztdc"
    )
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 10
    DB_ECHO: bool = False
    
    # Redis
    REDIS_URL: RedisDsn = Field(
        default="redis://:changeme123@localhost:6379/0"
    )
    REDIS_SESSION_TTL: int = 3600
    REDIS_CACHE_TTL: int = 300
    
    # Security
    JWT_SECRET_KEY: str = Field(
        default_factory=lambda: secrets.token_urlsafe(32)
    )
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE: int = 900  # 15 minutes
    JWT_REFRESH_TOKEN_EXPIRE: int = 604800  # 7 days
    
    ENCRYPTION_KEY: str = Field(
        default_factory=lambda: secrets.token_urlsafe(32)
    )
    PASSWORD_MIN_LENGTH: int = 12
    PASSWORD_REQUIRE_SPECIAL: bool = True
    PASSWORD_REQUIRE_DIGITS: bool = True
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    
    # TLS/SSL
    USE_TLS: bool = True
    CERT_DIR: str = "/app/certs"
    CA_CERT_FILE: str = "ca.crt"
    CA_KEY_FILE: str = "ca.key"
    SERVER_CERT_FILE: str = "server.crt"
    SERVER_KEY_FILE: str = "server.key"
    CA_PASSPHRASE: str = Field(
        default_factory=lambda: secrets.token_urlsafe(32)
    )
    CERT_VALIDITY_DAYS: int = 365
    AUTO_INIT_CA: bool = True
    
    # Identity Provider
    OIDC_ENABLED: bool = True
    SAML_ENABLED: bool = True
    OAUTH2_ENABLED: bool = True
    OIDC_ISSUER: Optional[str] = None
    
    @field_validator("OIDC_ISSUER")
    @classmethod
    def set_oidc_issuer(cls, v, info):
        if v is None:
            domain = info.data.get("DOMAIN_NAME", "localhost:8443")
            return f"https://{domain}"
        return v
    
    # Zero-Trust Configuration
    MTLS_REQUIRED: bool = False
    DEVICE_TRUST_REQUIRED: bool = False
    CONTINUOUS_AUTH_INTERVAL: int = 3600  # 1 hour
    MAX_SESSION_AGE: int = 28800  # 8 hours
    SESSION_INACTIVITY_TIMEOUT: int = 1800  # 30 minutes
    RISK_SCORE_THRESHOLD: float = 0.7
    
    # MFA Configuration
    MFA_REQUIRED: bool = True
    TOTP_ENABLED: bool = True
    TOTP_ISSUER: Optional[str] = None
    WEBAUTHN_ENABLED: bool = True
    WEBAUTHN_RP_NAME: str = "Zero-Trust DC"
    SMS_MFA_ENABLED: bool = False
    
    @field_validator("TOTP_ISSUER")
    @classmethod
    def set_totp_issuer(cls, v, info):
        if v is None:
            return info.data.get("ORGANIZATION", "Zero-Trust DC")
        return v
    
    # Policy Engine
    POLICY_ENGINE: str = "internal"  # internal or opa
    OPA_URL: Optional[str] = None
    DEFAULT_POLICY: str = "deny"  # deny or allow
    POLICY_CACHE_TTL: int = 300
    
    # LDAP Configuration
    LDAP_ENABLED: bool = True
    LDAP_PORT: int = 389
    LDAPS_PORT: int = 636
    LDAP_BIND_DN: Optional[str] = None
    
    @field_validator("LDAP_BIND_DN")
    @classmethod
    def set_ldap_bind_dn(cls, v, info):
        if v is None:
            return f"cn=admin,{info.data.get('BASE_DN', 'dc=example,dc=com')}"
        return v
    
    # Rate Limiting
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_PER_HOUR: int = 1000
    
    # CORS
    ALLOWED_ORIGINS: List[str] = ["*"]
    ALLOWED_HOSTS: List[str] = ["*"]
    
    # Monitoring
    PROMETHEUS_ENABLED: bool = True
    METRICS_PORT: int = 9443
    ENABLE_REQUEST_METRICS: bool = True
    
    # Audit Logging
    AUDIT_LOG_ENABLED: bool = True
    AUDIT_LOG_FILE: str = "/app/logs/audit.log"
    AUDIT_LOG_RETENTION_DAYS: int = 90
    
    # Feature Flags
    ENABLE_PASSWORD_RESET: bool = True
    ENABLE_USER_REGISTRATION: bool = False
    ENABLE_DEVICE_ENROLLMENT: bool = True
    ENABLE_RISK_SCORING: bool = True


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()