"""
Zero-Trust Domain Controller

Main application entry point.

PROTOTYPE NOTICE:
This is an alpha/prototype implementation. See PROJECT_STATUS.md for details.
"""

import sys
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import make_asgi_app
import uvicorn

from app.core.config import get_settings, validate_startup_config
from app.core.logging_config import configure_logging
from app.core.database import init_db, check_db_connection
from app.api import api_router

# Configure logging first
configure_logging()
logger = logging.getLogger(__name__)

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    
    Handles startup and shutdown events.
    """
    # Startup
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info(f"Environment: {settings.ENVIRONMENT}")
    
    try:
        # Validate configuration
        validate_startup_config()
        
        # Initialize database (create tables if needed)
        # Note: In production, use Alembic migrations instead
        if settings.DEBUG:
            logger.info("Initializing database tables (DEBUG mode)...")
            await init_db()
        
        # Check database connection
        db_healthy = await check_db_connection()
        if not db_healthy:
            logger.error("Database connection failed at startup")
            if settings.ENVIRONMENT == "production":
                raise RuntimeError("Cannot start without database connection")
        
        logger.info("Application startup complete")
        
    except Exception as e:
        logger.error(f"Startup failed: {e}")
        if settings.ENVIRONMENT == "production":
            sys.exit(1)
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down application")


# Create FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    description="Enterprise Zero-Trust Domain Controller with Integrated Identity Provider",
    version=settings.APP_VERSION,
    docs_url="/api/docs" if settings.DEBUG else None,
    redoc_url="/api/redoc" if settings.DEBUG else None,
    lifespan=lifespan,
)

# Add CORS middleware
if settings.ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Add trusted host middleware
if settings.ALLOWED_HOSTS:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.ALLOWED_HOSTS,
    )

# Include API router
app.include_router(api_router, prefix="/api/v1")


# Root endpoint
@app.get("/")
async def root():
    """
    API information endpoint.
    
    Note: Admin UI is not yet implemented. See PROJECT_STATUS.md
    """
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "alpha",
        "environment": settings.ENVIRONMENT,
        "domain": settings.DOMAIN_NAME,
        "endpoints": {
            "api": "/api/v1",
            "health": "/health",
            "ready": "/ready",
            "metrics": "/metrics",
            "docs": "/api/docs" if settings.DEBUG else "disabled",
            "oidc_discovery": "/.well-known/openid-configuration",
            "saml_metadata": "/saml/metadata",
        },
        "warnings": [
            "This is a PROTOTYPE implementation",
            "Many features are incomplete or stubbed",
            "See PROJECT_STATUS.md before use",
        ]
    }


# Health check endpoint
@app.get("/health")
async def health():
    """
    Liveness probe endpoint.
    
    Returns basic service status.
    """
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
    }


# Readiness check endpoint
@app.get("/ready")
async def ready():
    """
    Readiness probe endpoint.
    
    Checks that all dependencies are available.
    """
    checks = {
        "service": "ready",
        "database": await check_db_connection(),
        "redis": True,  # TODO: Implement Redis health check
        "ca": True,  # TODO: Implement CA health check
    }
    
    all_ready = all(checks.values())
    status_code = 200 if all_ready else 503
    
    return JSONResponse(
        status_code=status_code,
        content=checks,
    )


# OIDC Discovery endpoint (spec-compliant location)
# This is mounted at root level as per OIDC spec
@app.get("/.well-known/openid-configuration")
async def oidc_discovery(request: Request):
    """
    OIDC Discovery endpoint.
    
    Per OpenID Connect Discovery spec, this MUST be at
    /.well-known/openid-configuration relative to the issuer.
    
    Note: Most OIDC endpoints are not yet implemented (return 501).
    See PROJECT_STATUS.md for details.
    """
    base_url = str(request.base_url).rstrip("/")
    issuer = settings.get_oidc_issuer()
    
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{base_url}/api/v1/oidc/authorize",
        "token_endpoint": f"{base_url}/api/v1/oidc/token",
        "userinfo_endpoint": f"{base_url}/api/v1/oidc/userinfo",
        "jwks_uri": f"{base_url}/api/v1/oidc/jwks",
        "response_types_supported": ["code", "token", "id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "claims_supported": [
            "sub", "iss", "aud", "exp", "iat",
            "name", "email", "email_verified",
            "given_name", "family_name"
        ],
        "_warning": "OIDC endpoints are not fully implemented. See PROJECT_STATUS.md"
    }


# SAML Metadata endpoint (root level for spec compliance)
@app.get("/saml/metadata")
async def saml_metadata(request: Request):
    """
    SAML 2.0 Metadata endpoint.
    
    Returns IdP metadata XML.
    
    Note: This is a minimal stub. Full SAML implementation is not complete.
    See PROJECT_STATUS.md for details.
    """
    base_url = str(request.base_url).rstrip("/")
    entity_id = f"{base_url}/saml/metadata"
    
    metadata_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  entityID="{entity_id}">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                        Location="{base_url}/api/v1/saml/sso"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                        Location="{base_url}/api/v1/saml/sso"/>
  </IDPSSODescriptor>
  <!-- WARNING: SAML SSO is not fully implemented. See PROJECT_STATUS.md -->
</EntityDescriptor>'''
    
    return JSONResponse(
        content=metadata_xml,
        media_type="application/xml",
    )


# Prometheus metrics
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)


# Error handlers
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Global exception handler.
    
    Logs unexpected errors and returns a generic error response.
    """
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "message": "An unexpected error occurred",
            "detail": str(exc) if settings.DEBUG else "Contact support",
        },
    )


if __name__ == "__main__":
    # Run with uvicorn
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        ssl_keyfile=settings.TLS_KEY_FILE if not settings.DEBUG else None,
        ssl_certfile=settings.TLS_CERT_FILE if not settings.DEBUG else None,
        log_level=settings.LOG_LEVEL.lower(),
    )
