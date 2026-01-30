#!/usr/bin/env python3
"""
Zero-Trust Domain Controller Management CLI

Provides administrative commands for managing the domain controller.
"""

import asyncio
import sys
from pathlib import Path

import click
import structlog
from passlib.context import CryptContext

from app.core.config import get_settings
from app.core.logging_config import configure_logging
from app.core.database import init_database, close_database
from app.core.certificate_authority import init_ca, get_ca
from app.services.auth_service import AuthService

# Configure logging
configure_logging()
logger = structlog.get_logger(__name__)
settings = get_settings()
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


@click.group()
def cli():
    """Zero-Trust Domain Controller Management CLI."""
    pass


@cli.command()
def init_domain():
    """
    Initialize the domain controller.
    
    This command:
    - Initializes the database
    - Creates the Certificate Authority
    - Generates server certificates
    """
    click.echo("🚀 Initializing Zero-Trust Domain Controller...")
    
    async def _init():
        try:
            # Initialize database
            click.echo("📊 Initializing database...")
            await init_database()
            click.echo("✅ Database initialized")
            
            # Initialize CA
            click.echo("🔐 Initializing Certificate Authority...")
            await init_ca()
            click.echo("✅ Certificate Authority initialized")
            
            # Generate server certificate
            click.echo("🔑 Generating server certificate...")
            ca = get_ca()
            cert_pem, key_pem = await ca.issue_server_certificate(
                common_name=settings.DOMAIN_NAME,
                san_list=[settings.DOMAIN_NAME, f"*.{settings.DOMAIN_NAME}", "localhost"],
            )
            
            # Save server certificate and key
            cert_dir = Path(settings.CERT_DIR)
            with open(cert_dir / settings.SERVER_CERT_FILE, "wb") as f:
                f.write(cert_pem)
            with open(cert_dir / settings.SERVER_KEY_FILE, "wb") as f:
                f.write(key_pem)
            
            click.echo("✅ Server certificate generated")
            
            await close_database()
            
            click.echo("\n✨ Domain controller initialized successfully!")
            click.echo(f"\n🌐 Domain: {settings.DOMAIN_NAME}")
            click.echo(f"📁 Certificates: {cert_dir}")
            click.echo(f"\n⚠️  Remember to create an admin user with: python manage.py create-admin")
            
        except Exception as e:
            click.echo(f"\n❌ Initialization failed: {str(e)}", err=True)
            sys.exit(1)
    
    asyncio.run(_init())


@cli.command()
@click.option('--username', prompt=True, help='Admin username')
@click.option('--email', prompt=True, help='Admin email')
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True, help='Admin password')
def create_admin(username: str, email: str, password: str):
    """
    Create an administrative user.
    """
    click.echo(f"\n👤 Creating admin user: {username}")
    
    async def _create_admin():
        try:
            await init_database()
            
            # Validate password
            auth_service = AuthService()
            valid, message = auth_service.validate_password_strength(password)
            
            if not valid:
                click.echo(f"❌ Password validation failed: {message}", err=True)
                sys.exit(1)
            
            # Hash password
            hashed_password = auth_service.hash_password(password)
            
            # TODO: Create user in database
            # For now, just print the hashed password
            click.echo("\n✅ Admin user would be created with:")
            click.echo(f"   Username: {username}")
            click.echo(f"   Email: {email}")
            click.echo(f"   Password Hash: {hashed_password[:50]}...")
            click.echo("\n⚠️  Note: Database user creation not yet implemented")
            click.echo("    Add user creation logic to manage.py")
            
            await close_database()
            
        except Exception as e:
            click.echo(f"\n❌ Failed to create admin: {str(e)}", err=True)
            sys.exit(1)
    
    asyncio.run(_create_admin())


@cli.command()
@click.option('--username', prompt=True, help='Username')
@click.option('--device-id', default=None, help='Device ID (optional)')
def issue_certificate(username: str, device_id: str):
    """
    Issue a client certificate for mTLS authentication.
    """
    click.echo(f"\n🔑 Issuing certificate for: {username}")
    
    async def _issue_cert():
        try:
            await init_ca()
            ca = get_ca()
            
            cert_pem, key_pem = await ca.issue_client_certificate(username, device_id)
            
            # Save certificate and key
            output_dir = Path("./client-certs")
            output_dir.mkdir(exist_ok=True)
            
            cert_file = output_dir / f"{username}.crt"
            key_file = output_dir / f"{username}.key"
            
            with open(cert_file, "wb") as f:
                f.write(cert_pem)
            with open(key_file, "wb") as f:
                f.write(key_pem)
            
            click.echo(f"\n✅ Certificate issued successfully!")
            click.echo(f"   Certificate: {cert_file}")
            click.echo(f"   Private Key: {key_file}")
            click.echo(f"\n⚠️  Keep the private key secure!")
            
        except Exception as e:
            click.echo(f"\n❌ Failed to issue certificate: {str(e)}", err=True)
            sys.exit(1)
    
    asyncio.run(_issue_cert())


@cli.command()
def health_check():
    """
    Perform a health check on the domain controller.
    """
    click.echo("🏥 Performing health check...\n")
    
    # Check configuration
    click.echo("⚙️  Configuration:")
    click.echo(f"   Domain: {settings.DOMAIN_NAME}")
    click.echo(f"   OIDC Enabled: {settings.OIDC_ENABLED}")
    click.echo(f"   SAML Enabled: {settings.SAML_ENABLED}")
    click.echo(f"   MFA Required: {settings.MFA_REQUIRED}")
    click.echo(f"   mTLS Required: {settings.MTLS_REQUIRED}")
    
    # Check certificates
    click.echo("\n🔐 Certificates:")
    cert_dir = Path(settings.CERT_DIR)
    if cert_dir.exists():
        ca_cert = cert_dir / settings.CA_CERT_FILE
        server_cert = cert_dir / settings.SERVER_CERT_FILE
        click.echo(f"   CA Certificate: {'✅' if ca_cert.exists() else '❌'}")
        click.echo(f"   Server Certificate: {'✅' if server_cert.exists() else '❌'}")
    else:
        click.echo("   ❌ Certificate directory not found")
    
    # Check database connection
    click.echo("\n📊 Database:")
    click.echo(f"   URL: {settings.DATABASE_URL}")
    click.echo("   Connection: ⚠️  Not tested (requires async context)")
    
    click.echo("\n✅ Health check complete")


@cli.command()
@click.option('--format', type=click.Choice(['json', 'table']), default='table', help='Output format')
def show_config(format: str):
    """
    Display current configuration.
    """
    import json
    from pydantic import BaseModel
    
    config_dict = settings.model_dump()
    
    # Redact sensitive values
    sensitive_keys = ['PASSWORD', 'SECRET', 'KEY', 'PASSPHRASE']
    for key in config_dict:
        if any(sensitive in key.upper() for sensitive in sensitive_keys):
            config_dict[key] = '***REDACTED***'
    
    if format == 'json':
        click.echo(json.dumps(config_dict, indent=2, default=str))
    else:
        click.echo("\n⚙️  Current Configuration:\n")
        for key, value in sorted(config_dict.items()):
            click.echo(f"   {key}: {value}")


@cli.command()
def version():
    """
    Show version information.
    """
    from app import __version__
    
    click.echo(f"\nZero-Trust Domain Controller v{__version__}")
    click.echo(f"Python: {sys.version.split()[0]}")
    click.echo(f"Domain: {settings.DOMAIN_NAME}")
    click.echo()


if __name__ == '__main__':
    cli()