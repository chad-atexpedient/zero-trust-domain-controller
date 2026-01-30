"""API routes package."""

from fastapi import APIRouter

from app.api import auth, users, policies, oidc, saml

api_router = APIRouter()

# Include sub-routers
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(users.router, prefix="/users", tags=["Users"])
api_router.include_router(policies.router, prefix="/policies", tags=["Policies"])
api_router.include_router(oidc.router, prefix="/oidc", tags=["OIDC"])
api_router.include_router(saml.router, prefix="/saml", tags=["SAML"])

__all__ = ["api_router"]