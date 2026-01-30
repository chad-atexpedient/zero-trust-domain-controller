"""OpenID Connect (OIDC) endpoints."""

import structlog
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.core.config import get_settings

logger = structlog.get_logger(__name__)
settings = get_settings()
router = APIRouter()


class OIDCDiscovery(BaseModel):
    """OIDC discovery document."""
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str
    response_types_supported: list[str]
    subject_types_supported: list[str]
    id_token_signing_alg_values_supported: list[str]
    scopes_supported: list[str]
    token_endpoint_auth_methods_supported: list[str]
    claims_supported: list[str]


@router.get("/.well-known/openid-configuration", response_model=OIDCDiscovery)
async def oidc_discovery():
    """
    OIDC Discovery endpoint.
    
    Returns the OpenID Connect configuration for this identity provider.
    """
    if not settings.OIDC_ENABLED:
        raise HTTPException(status_code=404, detail="OIDC not enabled")
    
    return OIDCDiscovery(
        issuer=settings.OIDC_ISSUER,
        authorization_endpoint=f"{settings.OIDC_ISSUER}/oauth2/authorize",
        token_endpoint=f"{settings.OIDC_ISSUER}/oauth2/token",
        userinfo_endpoint=f"{settings.OIDC_ISSUER}/oauth2/userinfo",
        jwks_uri=f"{settings.OIDC_ISSUER}/oauth2/jwks",
        response_types_supported=["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
        subject_types_supported=["public", "pairwise"],
        id_token_signing_alg_values_supported=["RS256", "ES256", "HS256"],
        scopes_supported=["openid", "profile", "email", "address", "phone", "offline_access"],
        token_endpoint_auth_methods_supported=["client_secret_basic", "client_secret_post", "private_key_jwt"],
        claims_supported=["sub", "name", "given_name", "family_name", "email", "email_verified", "phone_number", "phone_number_verified", "address"],
    )


@router.get("/jwks")
async def jwks():
    """
    JSON Web Key Set endpoint.
    
    Returns the public keys used to verify JWT signatures.
    """
    if not settings.OIDC_ENABLED:
        raise HTTPException(status_code=404, detail="OIDC not enabled")
    
    # TODO: Implement actual JWKS from CA
    return {"keys": []}


@router.post("/token")
async def token():
    """
    OAuth 2.0 / OIDC token endpoint.
    
    Issues access tokens, refresh tokens, and ID tokens.
    """
    if not settings.OIDC_ENABLED:
        raise HTTPException(status_code=404, detail="OIDC not enabled")
    
    # TODO: Implement OAuth 2.0 token flow
    raise HTTPException(status_code=501, detail="Not implemented")


@router.get("/userinfo")
async def userinfo():
    """
    OIDC UserInfo endpoint.
    
    Returns claims about the authenticated user.
    """
    if not settings.OIDC_ENABLED:
        raise HTTPException(status_code=404, detail="OIDC not enabled")
    
    # TODO: Implement userinfo endpoint
    raise HTTPException(status_code=501, detail="Not implemented")