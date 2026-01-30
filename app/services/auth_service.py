"""Authentication and authorization service."""

import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

import jwt
import pyotp
import structlog
from passlib.context import CryptContext

from app.core.config import get_settings

logger = structlog.get_logger(__name__)
settings = get_settings()

# Password hashing context
pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
    argon2__memory_cost=65536,
    argon2__time_cost=3,
    argon2__parallelism=4,
)


class AuthService:
    """Service for authentication and authorization operations."""
    
    def __init__(self):
        self.jwt_algorithm = settings.JWT_ALGORITHM
        self.jwt_secret = settings.JWT_SECRET_KEY
        self.access_token_expire = settings.JWT_ACCESS_TOKEN_EXPIRE
        self.refresh_token_expire = settings.JWT_REFRESH_TOKEN_EXPIRE
    
    async def initialize(self) -> None:
        """Initialize the authentication service."""
        logger.info("auth_service_initialized")
    
    def hash_password(self, password: str) -> str:
        """Hash a password using Argon2."""
        return pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
        try:
            return pwd_context.verify(plain_password, hashed_password)
        except Exception as e:
            logger.error("password_verification_failed", error=str(e))
            return False
    
    def create_access_token(
        self,
        subject: str,
        claims: Optional[Dict[str, Any]] = None,
        expires_delta: Optional[timedelta] = None,
    ) -> str:
        """Create a JWT access token."""
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(seconds=self.access_token_expire)
        
        to_encode = {
            "sub": subject,
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "access",
            "jti": secrets.token_urlsafe(16),
        }
        
        if claims:
            to_encode.update(claims)
        
        encoded_jwt = jwt.encode(
            to_encode,
            self.jwt_secret,
            algorithm=self.jwt_algorithm,
        )
        
        return encoded_jwt
    
    def create_refresh_token(
        self,
        subject: str,
        expires_delta: Optional[timedelta] = None,
    ) -> str:
        """Create a JWT refresh token."""
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(seconds=self.refresh_token_expire)
        
        to_encode = {
            "sub": subject,
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "refresh",
            "jti": secrets.token_urlsafe(16),
        }
        
        encoded_jwt = jwt.encode(
            to_encode,
            self.jwt_secret,
            algorithm=self.jwt_algorithm,
        )
        
        return encoded_jwt
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode a JWT token."""
        try:
            payload = jwt.decode(
                token,
                self.jwt_secret,
                algorithms=[self.jwt_algorithm],
            )
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("token_expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning("invalid_token", error=str(e))
            return None
    
    def generate_totp_secret(self) -> str:
        """Generate a TOTP secret for MFA."""
        return pyotp.random_base32()
    
    def generate_totp_uri(
        self,
        username: str,
        secret: str,
    ) -> str:
        """Generate a TOTP provisioning URI for QR code."""
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(
            name=username,
            issuer_name=settings.TOTP_ISSUER,
        )
    
    def verify_totp(self, secret: str, token: str) -> bool:
        """Verify a TOTP token."""
        try:
            totp = pyotp.TOTP(secret)
            return totp.verify(token, valid_window=1)
        except Exception as e:
            logger.error("totp_verification_failed", error=str(e))
            return False
    
    def calculate_risk_score(
        self,
        user_data: Dict[str, Any],
        request_data: Dict[str, Any],
    ) -> float:
        """Calculate a risk score for zero-trust continuous authentication."""
        risk_score = 0.0
        
        # Check for unusual access patterns
        if request_data.get("ip_address") != user_data.get("last_ip_address"):
            risk_score += 0.2
        
        if request_data.get("user_agent") != user_data.get("last_user_agent"):
            risk_score += 0.15
        
        # Check time since last authentication
        last_auth = user_data.get("last_authentication_time")
        if last_auth:
            time_diff = datetime.utcnow() - last_auth
            if time_diff.total_seconds() > settings.CONTINUOUS_AUTH_INTERVAL:
                risk_score += 0.3
        
        # Check for failed authentication attempts
        failed_attempts = user_data.get("failed_attempts", 0)
        risk_score += min(failed_attempts * 0.1, 0.3)
        
        # Device trust
        if settings.DEVICE_TRUST_REQUIRED:
            if not request_data.get("device_trusted"):
                risk_score += 0.4
        
        return min(risk_score, 1.0)
    
    def validate_password_strength(self, password: str) -> tuple[bool, str]:
        """Validate password strength according to policy."""
        if len(password) < settings.PASSWORD_MIN_LENGTH:
            return False, f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters"
        
        if settings.PASSWORD_REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"
        
        if settings.PASSWORD_REQUIRE_DIGITS and not any(c.isdigit() for c in password):
            return False, "Password must contain at least one digit"
        
        if settings.PASSWORD_REQUIRE_SPECIAL:
            special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            if not any(c in special_chars for c in password):
                return False, "Password must contain at least one special character"
        
        return True, "Password is strong"