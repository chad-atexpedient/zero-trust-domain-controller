# Zero-Trust Domain Controller with Integrated Identity Provider

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?logo=docker&logoColor=white)](https://www.docker.com/)
[![Kubernetes](https://img.shields.io/badge/kubernetes-%23326ce5.svg?logo=kubernetes&logoColor=white)](https://kubernetes.io/)
[![Status](https://img.shields.io/badge/Status-Alpha%20%2F%20Prototype-yellow)](PROJECT_STATUS.md)

## ⚠️ PROJECT STATUS

> **IMPORTANT: This is a PROTOTYPE / REFERENCE IMPLEMENTATION**  
> **DO NOT DEPLOY IN PRODUCTION AS-IS**
>
> Many core features are incomplete or exist as design placeholders. Authentication currently accepts any credentials, IdP flows are stubbed, and comprehensive testing is absent.
>
> 📖 **Read [PROJECT_STATUS.md](PROJECT_STATUS.md) for complete implementation status**

---

## 🔒 Overview

Enterprise-grade Zero-Trust Domain Controller with integrated Identity Provider designed for modern PaaS deployments. This solution demonstrates the architecture and patterns for implementing true zero-trust principles with continuous verification, least-privilege access, and breach assumption.

**What this project provides:**
- ✅ Reference architecture for zero-trust systems
- ✅ Production-ready Kubernetes deployment patterns
- ✅ Working Certificate Authority (CA) implementation
- ✅ FastAPI-based API framework with structured logging
- ✅ Comprehensive database schema

**What's NOT yet implemented:**
- ❌ Real authentication (currently accepts any credentials)
- ❌ OIDC/OAuth2/SAML flows (endpoints return 501)
- ❌ ABAC policy evaluation (always denies)
- ❌ LDAP directory service
- ❌ Device trust workflows
- ❌ Test suite

See [PROJECT_STATUS.md](PROJECT_STATUS.md) for detailed feature status.

---

## 🌟 Planned Features

### Zero-Trust Architecture
- **Never Trust, Always Verify**: Continuous authentication and authorization
- **Micro-segmentation**: Fine-grained network isolation
- **Least Privilege Access**: Dynamic permission assignment
- **Assume Breach**: Security monitoring and anomaly detection

### Identity Provider (IdP)
- **OIDC (OpenID Connect)**: Modern authentication protocol *(planned)*
- **SAML 2.0**: Enterprise SSO integration *(stub only)*
- **OAuth 2.0**: Secure API authorization *(planned)*
- **Multi-Factor Authentication (MFA)**: TOTP *(partial)*, WebAuthn *(planned)*, SMS *(planned)*
- **Passwordless Authentication**: FIDO2, biometric support *(planned)*

### Domain Controller
- **User & Group Management**: LDAP-compatible directory *(schema only, no LDAP server)*
- **Policy Engine**: Attribute-based access control (ABAC) *(stub only)*
- **Certificate Authority**: Internal PKI for mTLS ✅ **Implemented**
- **Audit Logging**: Comprehensive security event tracking *(configured but not used)*
- **Device Trust**: Device health verification and enrollment *(planned)*

### PaaS Integration
- **Container-Native**: Docker and Kubernetes ready ✅ **Implemented**
- **Service Mesh Compatible**: Istio, Linkerd integration *(planned)*
- **Cloud-Agnostic**: AWS, Azure, GCP deployment ✅ **Manifests ready**
- **API-First**: RESTful endpoints ✅ **Framework ready**
- **High Availability**: Distributed architecture support ✅ **K8s manifests**

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    API Gateway (FastAPI)                    │
│                    ✅ Implemented                            │
└────────────────────────┬────────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
┌───────▼────────┐ ┌────▼─────────┐ ┌───▼──────────────┐
│  Identity      │ │   Policy     │ │  Certificate     │
│  Provider      │ │   Engine     │ │  Authority       │
│  (IdP)         │ │   (ABAC)     │ │  (PKI)           │
│  ⚠️ Stub       │ │  ⚠️ Stub     │ │  ✅ Working      │
└───────┬────────┘ └────┬─────────┘ └───┬──────────────┘
        │                │                │
        └────────────────┼────────────────┘
                         │
                ┌────────▼────────┐
                │  Directory      │
                │  Service (LDAP) │
                │  ❌ Not impl    │
                └────────┬────────┘
                         │
                ┌────────▼────────┐
                │  PostgreSQL     │
                │  + Redis Cache  │
                │  ✅ Schema ready│
                └─────────────────┘
```

**Legend:**
- ✅ Fully implemented and functional
- ⚠️ Partial/stub implementation
- ❌ Planned but not implemented

---

## 🚀 Quick Start (Development / Demo Only)

### Prerequisites
- Docker 24+ and Docker Compose
- Python 3.11+
- OpenSSL 3.0+

⚠️ **Warning**: The quickstart demonstrates the system structure but uses placeholder authentication. Do not use for actual access control.

### Local Development

```bash
# Clone the repository
git clone https://github.com/chad-atexpedient/zero-trust-domain-controller.git
cd zero-trust-domain-controller

# Copy environment template
cp .env.example .env

# Generate secure keys (REQUIRED)
python3 -c "import secrets; print('JWT_SECRET_KEY=' + secrets.token_urlsafe(32))" >> .env
python3 -c "import secrets; print('ENCRYPTION_KEY=' + secrets.token_urlsafe(32))" >> .env
python3 -c "import secrets; print('CA_PASSPHRASE=' + secrets.token_urlsafe(32))" >> .env

# Start all services
docker-compose up -d

# Initialize the domain controller (creates CA, database)
docker-compose exec ztdc python manage.py init-domain

# ⚠️ Note: create-admin currently does NOT persist users to database
# This is a known limitation - see PROJECT_STATUS.md
docker-compose exec ztdc python manage.py create-admin \
  --username admin \
  --email admin@example.com \
  --password 'YourSecurePassword123!'
```

### Access Points

| Service | URL | Status |
|---------|-----|--------|
| API Base | https://localhost:8443/api/v1 | ✅ Working |
| Health Check | https://localhost:8443/health | ✅ Working |
| Readiness | https://localhost:8443/ready | ✅ Working |
| Metrics | https://localhost:8443/metrics | ✅ Working |
| API Docs | https://localhost:8443/api/docs | ✅ Working (DEBUG mode) |
| OIDC Discovery | https://localhost:8443/api/v1/oidc/.well-known/openid-configuration | ⚠️ Wrong path, stub |
| SAML Metadata | https://localhost:8443/api/v1/saml/metadata | ⚠️ Stub only |
| Admin UI | https://localhost:8443 | ❌ Not implemented |
| Grafana | http://localhost:3000 | ✅ Working |
| Prometheus | http://localhost:9090 | ✅ Working |

### Verification

```bash
# Check health
curl -k https://localhost:8443/health

# Expected response:
{
  "status": "healthy",
  "service": "zero-trust-domain-controller",
  "version": "1.0.0"
}
```

---

## 📋 Configuration

### Critical Environment Variables

```env
# Domain Configuration
DOMAIN_NAME=example.com
DOMAIN_REALM=EXAMPLE.COM
BASE_DN=dc=example,dc=com

# Database
DATABASE_URL=postgresql://ztdc:password@postgres:5432/ztdc
REDIS_URL=redis://redis:6379/0

# Security (REQUIRED - Generate unique values!)
JWT_SECRET_KEY=<generate-secure-key>
ENCRYPTION_KEY=<generate-secure-key>
CA_PASSPHRASE=<generate-secure-passphrase>

# CORS & Security (⚠️ Default '*' is insecure - change for production!)
ALLOWED_ORIGINS=https://yourdomain.com
ALLOWED_HOSTS=yourdomain.com,localhost

# Zero Trust Features (currently not fully enforced)
MTLS_REQUIRED=false
DEVICE_TRUST_REQUIRED=false
MFA_REQUIRED=false
CONTINUOUS_AUTH_INTERVAL=3600
```

⚠️ **Security Warning**: Default values include `ALLOWED_ORIGINS=*` and `ALLOWED_HOSTS=*`. These MUST be changed before any production deployment.

---

## 🔌 API Examples (Current State)

### Authentication (⚠️ Stub Implementation)

```bash
# Login endpoint exists but currently accepts ANY credentials
curl -X POST https://localhost:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "any_user",
    "password": "any_password"
  }'

# Returns JWT token even with invalid credentials
# DO NOT rely on this for actual authentication
```

### User Management (Dummy Data Only)

```bash
# Create User (not persisted to database)
curl -X POST https://localhost:8443/api/v1/users \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john.doe",
    "email": "john.doe@example.com",
    "password": "SecurePass123!",
    "groups": ["developers"]
  }'

# Get User (returns dummy data)
curl -X GET https://localhost:8443/api/v1/users/john.doe \
  -H "Authorization: Bearer <token>"
```

### Policy Management (Always Denies)

```bash
# Evaluate policy (currently returns default deny)
curl -X POST https://localhost:8443/api/v1/policies/evaluate \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "principal": "user:john.doe",
    "resource": "service:database",
    "action": "read"
  }'

# Always returns:
{
  "decision": "deny",
  "reason": "Default deny policy - no matching allow policies found"
}
```

---

## 🛡️ Security Features

### ✅ Implemented

#### Cryptography
- **Certificate Authority**: RSA 4096 root CA with encrypted keys
- **TLS Certificates**: Server and client cert generation
- **Password Hashing**: Argon2id implementation
- **JWT Tokens**: RS256 signing and verification

#### Infrastructure
- **Kubernetes Security**: RBAC, network policies, pod security standards
- **Secrets Management**: K8s secrets and ConfigMaps
- **Structured Logging**: JSON logs with audit channel

### ⚠️ Partially Implemented
- **MFA**: TOTP logic exists but not fully integrated
- **Risk Scoring**: Algorithm present but uses placeholder data
- **Audit Logging**: Channel configured but not used in code

### ❌ Not Implemented
- **Account Lockout**: Failed attempt tracking not wired
- **Session Management**: No database persistence
- **Rate Limiting**: Config exists, no enforcement
- **Device Trust**: No enrollment or verification
- **ABAC Evaluation**: Policy engine is stub

### Compliance (Aspirational)
- **SOC 2 Type II**: Controls designed but not implemented
- **GDPR**: Data model supports compliance, logic incomplete
- **HIPAA**: Architecture ready, enforcement incomplete
- **PCI DSS**: Patterns present, validation missing

---

## 📊 Monitoring

### Metrics (✅ Working)
- Prometheus metrics endpoint: `/metrics`
- Grafana dashboards included in `monitoring/`
- Current metrics: HTTP requests, response times, errors

### Logging (✅ Configured)
- Structured JSON logging
- Audit log channel (not yet used in code)
- Integration points for ELK, Splunk, Datadog

### Tracing (❌ Not Implemented)
- OpenTelemetry integration planned

---

## 🧪 Testing

⚠️ **No tests currently exist**

Planned test structure:
```bash
# Unit tests (to be created)
python -m pytest tests/unit

# Integration tests (to be created)
python -m pytest tests/integration

# Security tests (to be created)
python -m pytest tests/security
```

---

## 📚 Documentation

- **[PROJECT_STATUS.md](PROJECT_STATUS.md)** - Implementation status ⚠️ **Read this first!**
- [ARCHITECTURE.md](docs/ARCHITECTURE.md) - System architecture (design)
- [DEPLOYMENT.md](docs/DEPLOYMENT.md) - Deployment guide
- [SECURITY.md](SECURITY.md) - Security best practices
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
- [QUICKSTART.md](QUICKSTART.md) - Quick start guide

**Planned documentation:**
- API Reference (not yet created)
- Troubleshooting Guide (not yet created)

---

## 🤝 Contributing

Contributions are welcome! Priority areas:

1. **Database Models** - SQLAlchemy ORM layer
2. **Real Authentication** - Wire auth endpoints to database
3. **Tests** - Any tests (unit, integration, security)
4. **OIDC Implementation** - OAuth2 and OIDC flows
5. **Policy Engine** - ABAC evaluation logic

Please read [CONTRIBUTING.md](CONTRIBUTING.md) and [PROJECT_STATUS.md](PROJECT_STATUS.md) before contributing.

---

## 📄 License

Apache License 2.0 - see [LICENSE](LICENSE) for details.

---

## 🗺️ Roadmap

### Phase 1: Core Security (Critical)
- [ ] Implement real authentication with database
- [ ] Session management and persistence
- [ ] SQLAlchemy models for all tables
- [ ] Fail-fast on missing secrets
- [ ] Audit logging integration

### Phase 2: Identity Provider
- [ ] OAuth2 authorization flows
- [ ] OIDC token and userinfo endpoints
- [ ] Fix OIDC discovery path
- [ ] JWKS endpoint with real keys
- [ ] SAML implementation or removal

### Phase 3: Authorization
- [ ] ABAC policy evaluation engine
- [ ] Redis caching for policies
- [ ] Database integration for policies

### Phase 4: Testing & CI/CD
- [ ] Unit test suite
- [ ] Integration tests
- [ ] Security tests
- [ ] GitHub Actions CI pipeline

### Phase 5: Advanced Features
- [ ] WebAuthn/FIDO2 MFA
- [ ] Device trust workflows
- [ ] LDAP directory service
- [ ] Admin UI
- [ ] OpenTelemetry tracing

---

**Built as a reference implementation for zero-trust security architecture**

For questions or to report security issues, see [SECURITY.md](SECURITY.md)
