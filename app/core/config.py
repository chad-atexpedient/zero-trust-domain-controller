"""
Configuration Settings

Environment-based configuration using Pydantic Settings.
"""

import secrets
from typing import List, Optional
from pydantic import Field
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
    APP_NAME: str = "Zero-Trust Domain Controller"
    APP_VERSION: str = "1.0.0-alpha"
    DEBUG: bool = False
    ENVIRONMENT: str = Field(default="development", pattern="^(development|staging|production)$")
    
    # Domain Configuration
    DOMAIN_NAME: str = "example.com"
    DOMAIN_REALM: str = "EXAMPLE.COM"
    BASE_DN: str = "dc=example,dc=com"
    
    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8443
    WORKERS: int = 4
    
    # Security - CORS and Allowed Hosts
    # ⚠️ SECURITY WARNING: Default values are for development only!
    # In production, these MUST be set to specific domains.
    ALLOWED_ORIGINS: List[str] = Field(
        default_factory=lambda: [] if _is_production() else ["*"]
    )
    ALLOWED_HOSTS: List[str] = Field(
        default_factory=lambda: [] if _is_production() else ["*"]
    )
    
    # Database
    DATABASE_URL: str = "postgresql://ztdc:password@localhost:5432/ztdc"
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # JWT Configuration
    JWT_SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_SECONDS: int = 3600  # 1 hour
    
    # Encryption
    ENCRYPTION_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    
    # Certificate Authority
    CA_PASSPHRASE: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    CA_KEY_SIZE: int = 4096
    CA_VALIDITY_DAYS: int = 3650  # 10 years
    CERT_VALIDITY_DAYS: int = 365  # 1 year
    CA_DIR: str = "./ca"
    CERTS_DIR: str = "./certs"
    
    # LDAP Configuration
    LDAP_ENABLED: bool = False  # ⚠️ Not implemented yet
    LDAP_PORT: int = 389
    LDAPS_PORT: int = 636
    LDAP_BIND_DN: str = "cn=admin,dc=example,dc=com"
    LDAP_BIND_PASSWORD: str = "changeme"
    
    # Identity Provider (IdP)
    OIDC_ENABLED: bool = True
    SAML_ENABLED: bool = True
    OAUTH2_ENABLED: bool = True
    OIDC_ISSUER: Optional[str] = None  # Defaults to https://{DOMAIN_NAME}
    
    # Multi-Factor Authentication
    MFA_REQUIRED: bool = False
    TOTP_ENABLED: bool = True
    WEBAUTHN_ENABLED: bool = False  # ⚠️ Not implemented yet
    SMS_MFA_ENABLED: bool = False  # ⚠️ Not implemented yet
    TOTP_ISSUER: Optional[str] = None  # Defaults to APP_NAME
    
    # Zero-Trust Security
    MTLS_REQUIRED: bool = False
    DEVICE_TRUST_REQUIRED: bool = False
    CONTINUOUS_AUTH_INTERVAL: int = 3600  # Re-auth check every hour
    MAX_SESSION_AGE: int = 28800  # 8 hours
    RISK_SCORE_THRESHOLD: float = 70.0  # Out of 100
    
    # Account Security
    PASSWORD_MIN_LENGTH: int = 12
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_DIGITS: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True
    ACCOUNT_LOCKOUT_THRESHOLD: int = 5  # Failed attempts before lockout
    ACCOUNT_LOCKOUT_DURATION: int = 30  # Minutes
    
    # Session Management
    SESSION_TIMEOUT: int = 3600  # 1 hour
    SESSION_ABSOLUTE_TIMEOUT: int = 28800  # 8 hours
    IDLE_TIMEOUT: int = 1800  # 30 minutes
    
    # Rate Limiting
    RATE_LIMIT_ENABLED: bool = False  # ⚠️ Not implemented yet
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_PER_HOUR: int = 1000
    
    # Logging
    LOG_LEVEL: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    JSON_LOGS: bool = True
    AUDIT_LOG_ENABLED: bool = True
    AUDIT_LOG_FILE: str = "./logs/audit.log"
    
    # Monitoring
    METRICS_ENABLED: bool = True
    METRICS_PATH: str = "/metrics"
    TRACING_ENABLED: bool = False  # ⚠️ Not implemented yet
    
    # TLS/SSL
    TLS_CERT_FILE: str = "./certs/server.crt"
    TLS_KEY_FILE: str = "./certs/server.key"
    TLS_MIN_VERSION: str = "TLSv1.3"
    
    def get_oidc_issuer(self) -> str:
        """Get OIDC issuer URL."""
        if self.OIDC_ISSUER:
            return self.OIDC_ISSUER
        return f"https://{self.DOMAIN_NAME}"
    
    def get_totp_issuer(self) -> str:
        """Get TOTP issuer name."""
        if self.TOTP_ISSUER:
            return self.TOTP_ISSUER
        return self.APP_NAME
    
    def validate_security_config(self) -> List[str]:
        """
        Validate security configuration.
        
        Returns list of warnings/errors for insecure configurations.
        This should be called at startup in production.
        """
        warnings = []
        
        # Check for production environment
        if self.ENVIRONMENT == "production":
            # Check CORS
            if "*" in self.ALLOWED_ORIGINS:
                warnings.append("CRITICAL: ALLOWED_ORIGINS contains '*' in production")
            
            if not self.ALLOWED_ORIGINS:
                warnings.append("CRITICAL: ALLOWED_ORIGINS is empty in production")
            
            # Check allowed hosts
            if "*" in self.ALLOWED_HOSTS:
                warnings.append("CRITICAL: ALLOWED_HOSTS contains '*' in production")
            
            if not self.ALLOWED_HOSTS:
                warnings.append("CRITICAL: ALLOWED_HOSTS is empty in production")
            
            # Check secrets
            if len(self.JWT_SECRET_KEY) < 32:
                warnings.append("CRITICAL: JWT_SECRET_KEY is too short")
            
            if len(self.ENCRYPTION_KEY) < 32:
                warnings.append("CRITICAL: ENCRYPTION_KEY is too short")
            
            if len(self.CA_PASSPHRASE) < 16:
                warnings.append("CRITICAL: CA_PASSPHRASE is too weak")
            
            # Check for weak defaults
            if self.DATABASE_URL == "postgresql://ztdc:password@localhost:5432/ztdc":
                warnings.append("WARNING: Using default DATABASE_URL")
            
            if self.LDAP_BIND_PASSWORD == "changeme":
                warnings.append("WARNING: Using default LDAP_BIND_PASSWORD")
            
            # Check security features
            if not self.MFA_REQUIRED:
                warnings.append("WARNING: MFA is not required in production")
            
            if not self.TLS_MIN_VERSION == "TLSv1.3":
                warnings.append("WARNING: TLS version should be 1.3 in production")
        
        return warnings


def _is_production() -> bool:
    """Check if running in production based on ENVIRONMENT env var."""
    import os
    env = os.getenv("ENVIRONMENT", "development")
    return env == "production"


# Singleton instance
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get settings singleton."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def validate_startup_config():
    """
    Validate configuration at startup.
    
    In production, this will raise an exception if critical security
    issues are found. In development, it will log warnings.
    """
    settings = get_settings()
    warnings = settings.validate_security_config()
    
    if warnings:
        import logging
        logger = logging.getLogger(__name__)
        
        critical_warnings = [w for w in warnings if w.startswith("CRITICAL")]
        other_warnings = [w for w in warnings if not w.startswith("CRITICAL")]
        
        if critical_warnings:
            for warning in critical_warnings:
                logger.error(warning)
            
            if settings.ENVIRONMENT == "production":
                raise RuntimeError(
                    f"Cannot start in production with critical security issues:\n" +
                    "\n".join(critical_warnings)
                )
        
        for warning in other_warnings:
            logger.warning(warning)
