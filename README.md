# Zero-Trust Domain Controller with Integrated Identity Provider

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?logo=docker&logoColor=white)](https://www.docker.com/)
[![Kubernetes](https://img.shields.io/badge/kubernetes-%23326ce5.svg?logo=kubernetes&logoColor=white)](https://kubernetes.io/)

## 🔒 Overview

Enterprise-grade Zero-Trust Domain Controller with integrated Identity Provider designed for modern PaaS deployments. This solution implements true zero-trust architecture with continuous verification, least-privilege access, and breach assumption principles.

## 🌟 Key Features

### Zero-Trust Architecture
- **Never Trust, Always Verify**: Continuous authentication and authorization
- **Micro-segmentation**: Fine-grained network isolation
- **Least Privilege Access**: Dynamic permission assignment
- **Assume Breach**: Security monitoring and anomaly detection

### Identity Provider (IdP)
- **OIDC (OpenID Connect)**: Modern authentication protocol
- **SAML 2.0**: Enterprise SSO integration
- **OAuth 2.0**: Secure API authorization
- **Multi-Factor Authentication (MFA)**: TOTP, WebAuthn, SMS
- **Passwordless Authentication**: FIDO2, biometric support

### Domain Controller
- **User & Group Management**: LDAP-compatible directory
- **Policy Engine**: Attribute-based access control (ABAC)
- **Certificate Authority**: Internal PKI for mTLS
- **Audit Logging**: Comprehensive security event tracking
- **Device Trust**: Device health verification and enrollment

### PaaS Integration
- **Container-Native**: Docker and Kubernetes ready
- **Service Mesh Compatible**: Istio, Linkerd integration
- **Cloud-Agnostic**: AWS, Azure, GCP deployment
- **API-First**: RESTful and gRPC endpoints
- **High Availability**: Distributed architecture support

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    API Gateway (mTLS)                       │
└────────────────────────┬────────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
┌───────▼────────┐ ┌────▼─────────┐ ┌───▼──────────────┐
│  Identity      │ │   Policy     │ │  Certificate     │
│  Provider      │ │   Engine     │ │  Authority       │
│  (IdP)         │ │   (ABAC)     │ │  (PKI)           │
└───────┬────────┘ └────┬─────────┘ └───┬──────────────┘
        │                │                │
        └────────────────┼────────────────┘
                         │
                ┌────────▼────────┐
                │  Directory      │
                │  Service (LDAP) │
                └────────┬────────┘
                         │
                ┌────────▼────────┐
                │  PostgreSQL     │
                │  + Redis Cache  │
                └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Docker 24+ and Docker Compose
- Python 3.11+
- OpenSSL 3.0+

### Local Development

```bash
# Clone the repository
git clone https://github.com/chad-atexpedient/zero-trust-domain-controller.git
cd zero-trust-domain-controller

# Start all services
docker-compose up -d

# Initialize the domain controller
docker-compose exec ztdc python manage.py init-domain

# Create admin user
docker-compose exec ztdc python manage.py create-admin
```

The services will be available at:
- **Admin UI**: https://localhost:8443
- **OIDC Endpoint**: https://localhost:8443/.well-known/openid-configuration
- **SAML Metadata**: https://localhost:8443/saml/metadata
- **API**: https://localhost:8443/api/v1

### Kubernetes Deployment

```bash
# Apply the manifests
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/secrets.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml

# Check status
kubectl get pods -n zero-trust
```

## 📋 Configuration

### Environment Variables

```env
# Domain Configuration
DOMAIN_NAME=example.com
DOMAIN_REALM=EXAMPLE.COM
BASE_DN=dc=example,dc=com

# Database
DATABASE_URL=postgresql://ztdc:password@postgres:5432/ztdc
REDIS_URL=redis://redis:6379/0

# Security
JWT_SECRET_KEY=<generate-secure-key>
ENCRYPTION_KEY=<generate-secure-key>
CA_PASSPHRASE=<generate-secure-passphrase>

# Identity Provider
OIDC_ENABLED=true
SAML_ENABLED=true
OAUTH2_ENABLED=true

# Zero Trust
MTLS_REQUIRED=true
DEVICE_TRUST_REQUIRED=true
CONTINUOUS_AUTH_INTERVAL=3600
MAX_SESSION_AGE=28800

# MFA
MFA_REQUIRED=true
TOTP_ENABLED=true
WEBAUTHN_ENABLED=true
```

## 🔐 Zero-Trust Principles

### 1. Verify Explicitly
- Every request is authenticated using JWT + mTLS
- Device health attestation required
- Continuous re-authentication based on risk score

### 2. Least Privilege Access
- Dynamic ABAC policies
- Time-bound permissions
- Just-In-Time (JIT) access provisioning

### 3. Assume Breach
- End-to-end encryption
- Micro-segmentation by default
- Real-time security monitoring
- Automated threat response

## 🔌 API Examples

### Authentication

```bash
# OIDC Authentication Flow
curl -X POST https://localhost:8443/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=<auth_code>" \
  -d "client_id=<client_id>" \
  -d "client_secret=<client_secret>" \
  -d "redirect_uri=<redirect_uri>"
```

### User Management

```bash
# Create User
curl -X POST https://localhost:8443/api/v1/users \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john.doe",
    "email": "john.doe@example.com",
    "groups": ["developers"],
    "mfa_required": true
  }'

# Get User
curl -X GET https://localhost:8443/api/v1/users/john.doe \
  -H "Authorization: Bearer <token>"
```

### Policy Management

```bash
# Create Access Policy
curl -X POST https://localhost:8443/api/v1/policies \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "database-access",
    "effect": "allow",
    "principals": ["group:database-admins"],
    "resources": ["service:postgresql:*"],
    "conditions": {
      "device_trusted": true,
      "mfa_verified": true,
      "time_of_day": "09:00-17:00"
    }
  }'
```

## 🛡️ Security Features

### Cryptography
- **TLS 1.3**: All external communications
- **mTLS**: Service-to-service authentication
- **AES-256-GCM**: Data at rest encryption
- **RSA 4096 / ECDSA P-384**: Key pairs
- **Argon2id**: Password hashing

### Compliance
- **SOC 2 Type II**: Audit logging and controls
- **GDPR**: Data privacy and consent management
- **HIPAA**: PHI protection capabilities
- **PCI DSS**: Secure credential handling

## 📊 Monitoring

### Metrics
- Prometheus metrics endpoint: `/metrics`
- Grafana dashboards included in `monitoring/`
- Key metrics: auth success/failure, policy evaluations, latency

### Logging
- Structured JSON logging
- Integration with ELK, Splunk, Datadog
- Security event correlation

## 🧪 Testing

```bash
# Run unit tests
python -m pytest tests/unit

# Run integration tests
python -m pytest tests/integration

# Run security tests
python -m pytest tests/security

# Load testing
locust -f tests/load/locustfile.py
```

## 📚 Documentation

- [Architecture Guide](docs/architecture.md)
- [API Reference](docs/api-reference.md)
- [Deployment Guide](docs/deployment.md)
- [Security Best Practices](docs/security.md)
- [Troubleshooting](docs/troubleshooting.md)

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## 📄 License

Apache License 2.0 - see [LICENSE](LICENSE) for details.

## 🆘 Support

- Issues: [GitHub Issues](https://github.com/chad-atexpedient/zero-trust-domain-controller/issues)
- Security: Report vulnerabilities to security@example.com

## 🗺️ Roadmap

- [ ] WebAuthn/FIDO2 implementation
- [ ] Machine learning-based anomaly detection
- [ ] Extended SCIM 2.0 provisioning
- [ ] Hardware security module (HSM) integration
- [ ] Risk-based adaptive authentication
- [ ] Blockchain-based audit trail

---

**Built with ❤️ for zero-trust security**