"""
Authentication API Endpoints

PROTOTYPE NOTICE:
This implementation is currently a PROTOTYPE with critical security gaps:
- Database verification is implemented but requires init_db() to be called
- Session persistence is basic and needs production hardening
- Risk scoring uses limited heuristics
- MFA integration is partial

See PROJECT_STATUS.md for full details.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.config import get_settings
from app.services.auth_service import AuthService
from app.models.user import User
from app.models.session import Session as SessionModel
from app.models.mfa import MFASecret
from app.models.audit import AuditLog

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("audit")
settings = get_settings()
security = HTTPBearer()

router = APIRouter(prefix="/auth", tags=["authentication"])

# Request/Response Models


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=255)
    password: str = Field(..., min_length=1)
    mfa_token: Optional[str] = None
    device_id: Optional[str] = None


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    mfa_required: bool = False
    session_id: str


class RefreshRequest(BaseModel):
    refresh_token: str


class MFAEnrollRequest(BaseModel):
    method: str = Field(..., pattern="^(totp|webauthn|sms)$")
    device_name: Optional[str] = None


class MFAEnrollResponse(BaseModel):
    secret: Optional[str] = None
    qr_code_uri: Optional[str] = None
    backup_codes: Optional[list[str]] = None


class MFAVerifyRequest(BaseModel):
    token: str
    mfa_type: str = "totp"


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=12)


class MessageResponse(BaseModel):
    message: str


# Helper Functions


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Dependency to get current authenticated user from JWT token.
    """
    auth_service = AuthService()
    token = credentials.credentials
    
    try:
        payload = auth_service.verify_jwt_token(token)
        username = payload.get("sub")
        
        if not username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
            )
        
        # Get user from database
        stmt = select(User).where(User.username == username)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
            )
        
        if not user.enabled:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is disabled",
            )
        
        return user
        
    except Exception as e:
        logger.error(f"Authentication failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )


async def log_audit_event(
    db: AsyncSession,
    event_type: str,
    action: str,
    result: str,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    details: Optional[str] = None,
):
    """
    Log an audit event to both audit logger and database.
    """
    try:
        # Log to audit file
        audit_logger.info(
            event_type,
            extra={
                "action": action,
                "result": result,
                "user_id": user_id,
                "username": username,
                "ip_address": ip_address,
            }
        )
        
        # Log to database
        audit_log = AuditLog(
            event_type=event_type,
            event_category="authentication",
            user_id=user_id,
            username=username,
            action=action,
            result=result,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details,
            timestamp=datetime.utcnow(),
        )
        db.add(audit_log)
        await db.flush()
    except Exception as e:
        logger.error(f"Failed to log audit event: {e}")


# Endpoints


@router.post("/login", response_model=LoginResponse)
async def login(
    request: Request,
    login_data: LoginRequest,
    db: AsyncSession = Depends(get_db),
    user_agent: Optional[str] = Header(None),
):
    """
    Authenticate user and create session.
    
    WARNING: This implementation includes database verification but still has limitations:
    - Account lockout is checked but not fully enforced
    - Risk scoring uses basic heuristics
    - MFA is partially integrated
    
    See PROJECT_STATUS.md for details.
    """
    auth_service = AuthService()
    ip_address = request.client.host if request.client else None
    
    # Get user from database
    stmt = select(User).where(User.username == login_data.username)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    
    if not user:
        await log_audit_event(
            db=db,
            event_type="login_failed",
            action="login",
            result="failure",
            username=login_data.username,
            ip_address=ip_address,
            user_agent=user_agent,
            details="User not found",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    
    # Check if account is locked
    if user.account_locked and user.locked_until:
        if datetime.utcnow() < user.locked_until:
            await log_audit_event(
                db=db,
                event_type="login_blocked",
                action="login",
                result="blocked",
                user_id=user.id,
                username=user.username,
                ip_address=ip_address,
                user_agent=user_agent,
                details="Account locked",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account is locked until {user.locked_until.isoformat()}",
            )
        else:
            # Unlock account if lock period has passed
            user.account_locked = False
            user.locked_until = None
            user.failed_attempts = 0
    
    # Verify password
    if not auth_service.verify_password(login_data.password, user.password_hash):
        # Increment failed attempts
        user.failed_attempts += 1
        
        # Lock account if threshold exceeded
        if user.failed_attempts >= settings.ACCOUNT_LOCKOUT_THRESHOLD:
            user.account_locked = True
            user.locked_until = datetime.utcnow() + timedelta(minutes=settings.ACCOUNT_LOCKOUT_DURATION)
        
        await db.flush()
        
        await log_audit_event(
            db=db,
            event_type="login_failed",
            action="login",
            result="failure",
            user_id=user.id,
            username=user.username,
            ip_address=ip_address,
            user_agent=user_agent,
            details="Invalid password",
        )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    
    # Check if user is enabled
    if not user.enabled:
        await log_audit_event(
            db=db,
            event_type="login_blocked",
            action="login",
            result="blocked",
            user_id=user.id,
            username=user.username,
            ip_address=ip_address,
            user_agent=user_agent,
            details="Account disabled",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )
    
    # Check MFA requirement
    mfa_verified = False
    if user.mfa_enabled and user.mfa_required:
        if not login_data.mfa_token:
            # Return response indicating MFA required
            return LoginResponse(
                access_token="",
                refresh_token="",
                token_type="bearer",
                expires_in=0,
                mfa_required=True,
                session_id="",
            )
        
        # Verify MFA token
        stmt = select(MFASecret).where(
            MFASecret.user_id == user.id,
            MFASecret.is_active == True,
            MFASecret.mfa_type == "totp",
        )
        result = await db.execute(stmt)
        mfa_secret = result.scalar_one_or_none()
        
        if not mfa_secret:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA not enrolled",
            )
        
        if not auth_service.verify_totp(login_data.mfa_token, mfa_secret.secret):
            await log_audit_event(
                db=db,
                event_type="mfa_failed",
                action="mfa_verify",
                result="failure",
                user_id=user.id,
                username=user.username,
                ip_address=ip_address,
                user_agent=user_agent,
                details="Invalid MFA token",
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid MFA token",
            )
        
        mfa_verified = True
        mfa_secret.last_used = datetime.utcnow()
    
    # Calculate risk score
    risk_score = auth_service.calculate_risk_score(
        ip_address=ip_address or "unknown",
        user_agent=user_agent or "unknown",
        last_login_ip=ip_address or "unknown",  # TODO: Get from last session
        last_login_user_agent=user_agent or "unknown",
        failed_attempts=user.failed_attempts,
        time_since_last_login=3600,  # TODO: Calculate from last session
    )
    
    if risk_score > settings.RISK_SCORE_THRESHOLD:
        await log_audit_event(
            db=db,
            event_type="login_blocked",
            action="login",
            result="blocked",
            user_id=user.id,
            username=user.username,
            ip_address=ip_address,
            user_agent=user_agent,
            details=f"High risk score: {risk_score}",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Login blocked due to risk assessment. Additional verification required.",
        )
    
    # Generate tokens
    access_token = auth_service.create_jwt_token(username=user.username)
    refresh_token = auth_service.create_jwt_token(
        username=user.username,
        token_type="refresh",
        expires_delta=timedelta(days=30),
    )
    
    # Create session
    session_id = f"sess_{datetime.utcnow().timestamp()}_{user.id}"
    session = SessionModel(
        session_id=session_id,
        user_id=user.id,
        ip_address=ip_address,
        user_agent=user_agent,
        device_id=login_data.device_id,
        risk_score=risk_score,
        mfa_verified=mfa_verified,
        device_trusted=False,  # TODO: Implement device trust checking
        access_token=access_token,
        refresh_token=refresh_token,
        expires_at=datetime.utcnow() + timedelta(seconds=settings.JWT_EXPIRATION_SECONDS),
        last_activity=datetime.utcnow(),
        is_active=True,
    )
    db.add(session)
    
    # Update user
    user.last_login = datetime.utcnow()
    user.failed_attempts = 0
    
    await db.flush()
    
    await log_audit_event(
        db=db,
        event_type="login_success",
        action="login",
        result="success",
        user_id=user.id,
        username=user.username,
        ip_address=ip_address,
        user_agent=user_agent,
        details=f"Session ID: {session_id}",
    )
    
    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.JWT_EXPIRATION_SECONDS,
        mfa_required=False,
        session_id=session_id,
    )


@router.post("/refresh", response_model=LoginResponse)
async def refresh_token(
    refresh_data: RefreshRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Refresh access token using refresh token.
    """
    auth_service = AuthService()
    
    try:
        payload = auth_service.verify_jwt_token(refresh_data.refresh_token)
        username = payload.get("sub")
        token_type = payload.get("type")
        
        if token_type != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
            )
        
        # Get user from database
        stmt = select(User).where(User.username == username)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()
        
        if not user or not user.enabled:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )
        
        # Generate new access token
        access_token = auth_service.create_jwt_token(username=user.username)
        
        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_data.refresh_token,
            token_type="bearer",
            expires_in=settings.JWT_EXPIRATION_SECONDS,
            mfa_required=False,
            session_id="",  # TODO: Update existing session
        )
        
    except Exception as e:
        logger.error(f"Token refresh failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )


@router.post("/mfa/enroll", response_model=MFAEnrollResponse)
async def enroll_mfa(
    enroll_data: MFAEnrollRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Enroll in MFA.
    
    Currently supports:
    - TOTP: Full implementation
    - WebAuthn: Not implemented (501)
    - SMS: Not implemented (501)
    """
    auth_service = AuthService()
    
    if enroll_data.method == "totp":
        # Generate TOTP secret
        secret = auth_service.generate_totp_secret()
        uri = auth_service.get_totp_uri(secret, user.username, settings.DOMAIN_NAME)
        
        # Save to database
        mfa_secret = MFASecret(
            user_id=user.id,
            mfa_type="totp",
            secret=secret,
            device_name=enroll_data.device_name or "TOTP Authenticator",
            is_active=True,
        )
        db.add(mfa_secret)
        
        # Enable MFA for user
        user.mfa_enabled = True
        
        await db.flush()
        
        return MFAEnrollResponse(
            secret=secret,
            qr_code_uri=uri,
        )
    
    elif enroll_data.method in ["webauthn", "sms"]:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=f"{enroll_data.method.upper()} MFA is not yet implemented. See PROJECT_STATUS.md",
        )
    
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid MFA method",
    )


@router.post("/password/change", response_model=MessageResponse)
async def change_password(
    password_data: PasswordChangeRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Change user password.
    """
    auth_service = AuthService()
    
    # Verify current password
    if not auth_service.verify_password(password_data.current_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect",
        )
    
    # Hash new password
    new_hash = auth_service.hash_password(password_data.new_password)
    
    # Update user
    user.password_hash = new_hash
    user.password_changed_at = datetime.utcnow()
    
    await db.flush()
    
    await log_audit_event(
        db=db,
        event_type="password_changed",
        action="password_change",
        result="success",
        user_id=user.id,
        username=user.username,
    )
    
    return MessageResponse(message="Password changed successfully")


@router.post("/logout", response_model=MessageResponse)
async def logout(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """
    Logout user and invalidate session.
    """
    # Find and deactivate session
    stmt = select(SessionModel).where(
        SessionModel.user_id == user.id,
        SessionModel.access_token == credentials.credentials,
        SessionModel.is_active == True,
    )
    result = await db.execute(stmt)
    session = result.scalar_one_or_none()
    
    if session:
        session.is_active = False
        await db.flush()
    
    await log_audit_event(
        db=db,
        event_type="logout",
        action="logout",
        result="success",
        user_id=user.id,
        username=user.username,
    )
    
    return MessageResponse(message="Successfully logged out")
