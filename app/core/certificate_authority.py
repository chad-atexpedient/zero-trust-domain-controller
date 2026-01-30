"""Internal Certificate Authority for mTLS and device certificates."""

import datetime
from pathlib import Path
from typing import Tuple

import structlog
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from app.core.config import get_settings

logger = structlog.get_logger(__name__)
settings = get_settings()


class CertificateAuthority:
    """Internal Certificate Authority for issuing certificates."""
    
    def __init__(self):
        self.cert_dir = Path(settings.CERT_DIR)
        self.ca_cert_path = self.cert_dir / settings.CA_CERT_FILE
        self.ca_key_path = self.cert_dir / settings.CA_KEY_FILE
        self.ca_cert = None
        self.ca_key = None
    
    async def initialize(self) -> None:
        """Initialize or load CA certificates."""
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        
        if self.ca_cert_path.exists() and self.ca_key_path.exists():
            logger.info("loading_existing_ca_certificates")
            self._load_ca()
        else:
            logger.info("generating_new_ca_certificates")
            await self._generate_ca()
    
    def _load_ca(self) -> None:
        """Load existing CA certificate and key."""
        with open(self.ca_cert_path, "rb") as f:
            self.ca_cert = x509.load_pem_x509_certificate(f.read())
        
        with open(self.ca_key_path, "rb") as f:
            self.ca_key = serialization.load_pem_private_key(
                f.read(),
                password=settings.CA_PASSPHRASE.encode(),
                backend=default_backend(),
            )
    
    async def _generate_ca(self) -> None:
        """Generate new CA certificate and key."""
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend(),
        )
        
        # Build subject and issuer
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, settings.ORGANIZATION),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Security"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{settings.DOMAIN_NAME} Root CA"),
        ])
        
        # Build certificate
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=3650)  # 10 years
            )
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .sign(private_key, hashes.SHA256(), backend=default_backend())
        )
        
        # Save CA certificate
        with open(self.ca_cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        # Save CA private key (encrypted)
        with open(self.ca_key_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.BestAvailableEncryption(
                        settings.CA_PASSPHRASE.encode()
                    ),
                )
            )
        
        self.ca_cert = cert
        self.ca_key = private_key
        
        logger.info("ca_certificates_generated")
    
    async def issue_server_certificate(
        self, common_name: str, san_list: list[str] = None
    ) -> Tuple[bytes, bytes]:
        """Issue a server certificate."""
        if not self.ca_cert or not self.ca_key:
            raise RuntimeError("CA not initialized")
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        
        # Build subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, settings.ORGANIZATION),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        # Build SAN extension
        san_list = san_list or [common_name]
        san_extension = x509.SubjectAlternativeName(
            [x509.DNSName(name) for name in san_list]
        )
        
        # Build certificate
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(
                datetime.datetime.utcnow()
                + datetime.timedelta(days=settings.CERT_VALIDITY_DAYS)
            )
            .add_extension(san_extension, critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=True,
            )
            .sign(self.ca_key, hashes.SHA256(), backend=default_backend())
        )
        
        # Return certificate and private key as PEM
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        
        return cert_pem, key_pem
    
    async def issue_client_certificate(
        self, username: str, device_id: str = None
    ) -> Tuple[bytes, bytes]:
        """Issue a client certificate for mTLS authentication."""
        if not self.ca_cert or not self.ca_key:
            raise RuntimeError("CA not initialized")
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        
        # Build subject
        common_name = f"{username}@{settings.DOMAIN_NAME}"
        if device_id:
            common_name = f"{username}.{device_id}@{settings.DOMAIN_NAME}"
        
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, settings.ORGANIZATION),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        # Build certificate
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(
                datetime.datetime.utcnow()
                + datetime.timedelta(days=settings.CERT_VALIDITY_DAYS)
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=True,
            )
            .sign(self.ca_key, hashes.SHA256(), backend=default_backend())
        )
        
        # Return certificate and private key as PEM
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        
        return cert_pem, key_pem


# Global CA instance
_ca_instance = None


async def init_ca() -> None:
    """Initialize the Certificate Authority."""
    global _ca_instance
    _ca_instance = CertificateAuthority()
    await _ca_instance.initialize()


def get_ca() -> CertificateAuthority:
    """Get the Certificate Authority instance."""
    if _ca_instance is None:
        raise RuntimeError("Certificate Authority not initialized")
    return _ca_instance