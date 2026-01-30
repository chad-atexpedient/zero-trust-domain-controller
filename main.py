#!/usr/bin/env python3
"""
Zero-Trust Domain Controller - Main Entry Point

This is the main entry point for the Zero-Trust Domain Controller.
It initializes and starts all required services.
"""

import asyncio
import logging
import signal
import sys
from pathlib import Path

import structlog
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from prometheus_client import make_asgi_app

from app.core.config import get_settings
from app.core.logging_config import configure_logging
from app.api import api_router
from app.core.database import init_database, close_database
from app.core.certificate_authority import init_ca
from app.services.auth_service import AuthService

# Configure structured logging
configure_logging()
logger = structlog.get_logger(__name__)

settings = get_settings()

# Create FastAPI application
app = FastAPI(
    title="Zero-Trust Domain Controller",
    description="Enterprise Zero-Trust Domain Controller with Integrated Identity Provider",
    version="1.0.0",
    docs_url="/api/docs" if settings.DEBUG else None,
    redoc_url="/api/redoc" if settings.DEBUG else None,
    openapi_url="/api/openapi.json" if settings.DEBUG else None,
)

# Add security middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.ALLOWED_HOSTS,
)

# Include API routes
app.include_router(api_router, prefix="/api/v1")

# Add Prometheus metrics endpoint
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)


@app.on_event("startup")
async def startup_event():
    """Initialize services on startup."""
    logger.info("starting_zero_trust_domain_controller", version="1.0.0")
    
    try:
        # Initialize database
        logger.info("initializing_database")
        await init_database()
        
        # Initialize Certificate Authority
        if settings.AUTO_INIT_CA:
            logger.info("initializing_certificate_authority")
            await init_ca()
        
        # Initialize auth service
        logger.info("initializing_auth_service")
        auth_service = AuthService()
        await auth_service.initialize()
        
        logger.info(
            "startup_complete",
            domain=settings.DOMAIN_NAME,
            oidc_enabled=settings.OIDC_ENABLED,
            saml_enabled=settings.SAML_ENABLED,
            mtls_required=settings.MTLS_REQUIRED,
        )
    except Exception as e:
        logger.error("startup_failed", error=str(e), exc_info=True)
        sys.exit(1)


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    logger.info("shutting_down_zero_trust_domain_controller")
    await close_database()
    logger.info("shutdown_complete")


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "zero-trust-domain-controller",
        "version": "1.0.0",
    }


@app.get("/ready")
async def readiness_check():
    """Readiness check endpoint."""
    # TODO: Add actual readiness checks (DB, Redis, etc.)
    return {
        "status": "ready",
        "checks": {
            "database": "ok",
            "redis": "ok",
            "ca": "ok",
        },
    }


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "Zero-Trust Domain Controller",
        "version": "1.0.0",
        "domain": settings.DOMAIN_NAME,
        "endpoints": {
            "api": "/api/v1",
            "oidc": "/.well-known/openid-configuration",
            "saml": "/saml/metadata",
            "health": "/health",
            "metrics": "/metrics",
        },
    }


def handle_signal(signum, frame):
    """Handle shutdown signals gracefully."""
    logger.info("received_shutdown_signal", signal=signum)
    sys.exit(0)


if __name__ == "__main__":
    # Register signal handlers
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    
    # Configure SSL/TLS
    ssl_keyfile = None
    ssl_certfile = None
    
    if settings.USE_TLS:
        cert_dir = Path(settings.CERT_DIR)
        ssl_keyfile = str(cert_dir / "server.key")
        ssl_certfile = str(cert_dir / "server.crt")
        
        # Generate self-signed cert if not exists and in dev mode
        if settings.DEBUG and not cert_dir.exists():
            logger.warning("generating_self_signed_certificate")
            cert_dir.mkdir(parents=True, exist_ok=True)
            # Certificate generation would happen here
    
    # Start the server
    logger.info(
        "starting_server",
        host=settings.HOST,
        port=settings.PORT,
        tls_enabled=settings.USE_TLS,
    )
    
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        ssl_keyfile=ssl_keyfile,
        ssl_certfile=ssl_certfile,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower(),
        access_log=True,
    )