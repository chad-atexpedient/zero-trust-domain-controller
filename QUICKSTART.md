# Quick Start Guide

⚠️ **IMPORTANT**: This is a PROTOTYPE implementation. Read [PROJECT_STATUS.md](PROJECT_STATUS.md) before proceeding.

Get your Zero-Trust Domain Controller demo running in 5 minutes!

## ⚠️ Current Limitations

Before starting, be aware:

- ✅ **Database and authentication** now work with real verification
- ⚠️ **create-admin command** is partially functional (see step 4 below)
- ❌ **OIDC/OAuth2 endpoints** return 501 Not Implemented
- ❌ **SAML SSO** is a stub only
- ❌ **Policy evaluation** always denies (stub)
- ❌ **User management APIs** use dummy data (not yet connected to database)

See [PROJECT_STATUS.md](PROJECT_STATUS.md) for complete status.

---

## Prerequisites

- Docker 24.0+
- Docker Compose 2.0+
- 4GB RAM minimum
- Ports 8443, 3000, 9090 available

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/chad-atexpedient/zero-trust-domain-controller.git
cd zero-trust-domain-controller
```

### 2. Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Generate secure keys (REQUIRED!)
python3 << 'EOF'
import secrets
print(f"JWT_SECRET_KEY={secrets.token_urlsafe(32)}")
print(f"ENCRYPTION_KEY={secrets.token_urlsafe(32)}")
print(f"CA_PASSPHRASE={secrets.token_urlsafe(32)}")
print(f"POSTGRES_PASSWORD={secrets.token_urlsafe(16)}")
print(f"REDIS_PASSWORD={secrets.token_urlsafe(16)}")
EOF

# Edit .env and paste the generated values
# Also update:
# - DOMAIN_NAME=your-domain.com (or localhost for testing)
# - ALLOWED_ORIGINS=https://your-domain.com (or http://localhost:3000 for local)
# - ALLOWED_HOSTS=your-domain.com,localhost
```

### 3. Start Services

```bash
# Start all services
docker-compose up -d

# Wait for services to be ready (30-60 seconds)
docker-compose ps

# All services should show "healthy" or "running"
```

### 4. Initialize Domain Controller

```bash
# Initialize the domain (creates database tables, CA, certificates)
docker-compose exec ztdc python manage.py init-domain

# ⚠️ IMPORTANT: create-admin currently has limitations
# It will hash the password and show you what would be created,
# but does NOT yet persist to the database.
docker-compose exec ztdc python manage.py create-admin \
  --username admin \
  --email admin@example.com \
  --password 'YourSecurePassword123!'

# Manual workaround: Create admin user directly in database
docker-compose exec postgres psql -U ztdc -d ztdc << 'EOF'
-- Get the password hash from the create-admin output above and use it here
INSERT INTO users (username, email, password_hash, enabled, mfa_required, created_at, updated_at)
VALUES ('admin', 'admin@example.com', 'PASTE_HASH_HERE', true, false, NOW(), NOW());

-- Get the user ID
SELECT id FROM users WHERE username = 'admin';

-- Add to admins group (assuming group IDs from init-db.sql)
INSERT INTO user_groups (user_id, group_id, created_at, updated_at)
VALUES (PASTE_USER_ID, 1, NOW(), NOW());
EOF
```

**Note**: A proper `create-admin` implementation is tracked in [FIXES_APPLIED.md](FIXES_APPLIED.md).

### 5. Verify Installation

```bash
# Check health
curl -k https://localhost:8443/health

# Expected output:
{
  "status": "healthy",
  "service": "Zero-Trust Domain Controller",
  "version": "1.0.0-alpha"
}

# Check readiness (includes database)
curl -k https://localhost:8443/ready

# View logs
docker-compose logs -f ztdc
```

---

## Access Points

Once running:

| Service | URL | Status | Notes |
|---------|-----|--------|-------|
| **API Base** | https://localhost:8443/api/v1 | ✅ Working | |
| **Health** | https://localhost:8443/health | ✅ Working | Liveness probe |
| **Ready** | https://localhost:8443/ready | ✅ Working | Readiness probe |
| **Metrics** | https://localhost:8443/metrics | ✅ Working | Prometheus |
| **API Docs** | https://localhost:8443/api/docs | ✅ Working | DEBUG mode only |
| **OIDC Discovery** | https://localhost:8443/.well-known/openid-configuration | ⚠️ Stub | Returns URLs but endpoints are 501 |
| **SAML Metadata** | https://localhost:8443/saml/metadata | ⚠️ Stub | XML stub only |
| **Admin UI** | https://localhost:8443 | ❌ Not implemented | Returns JSON, no UI |
| **Grafana** | http://localhost:3000 | ✅ Working | admin/admin |
| **Prometheus** | http://localhost:9090 | ✅ Working | |

---

## First API Calls

### 1. Login (✅ Now Works with Real Database)

```bash
# Login with the admin user you created
curl -k -X POST https://localhost:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "YourSecurePassword123!"
  }'

# Response includes:
# - access_token: JWT for API calls
# - refresh_token: For token refresh
# - session_id: Session identifier
```

**Note**: Authentication now performs real database verification, password checking, and audit logging. ✅

### 2. Create a User (⚠️ API Exists But Not Connected to Database Yet)

```bash
# Save the access_token from login
TOKEN="your-access-token-here"

# This endpoint exists but currently returns dummy data
# Database integration is pending
curl -k -X POST https://localhost:8443/api/v1/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john.doe",
    "email": "john.doe@example.com",
    "password": "SecurePassword123!",
    "first_name": "John",
    "last_name": "Doe",
    "groups": ["users"]
  }'
```

**Status**: User API models exist but endpoint not yet wired to database. See [FIXES_APPLIED.md](FIXES_APPLIED.md).

### 3. Create a Policy (⚠️ Stub Implementation)

```bash
# Policy API exists but evaluation always denies
curl -k -X POST https://localhost:8443/api/v1/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "api-read-access",
    "description": "Allow read access to API",
    "effect": "allow",
    "principals": ["group:users"],
    "resources": ["service:api:*"],
    "actions": ["read"],
    "priority": 100
  }'

# Policy evaluation
curl -k -X POST https://localhost:8443/api/v1/policies/evaluate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "principal": "user:john.doe",
    "resource": "service:api",
    "action": "read"
  }'

# Currently always returns:
# {"decision": "deny", "reason": "Default deny policy..."}
```

**Status**: Policy engine is a stub. ABAC implementation pending. See [PROJECT_STATUS.md](PROJECT_STATUS.md).

---

## Testing MFA (✅ TOTP Works)

### Enable TOTP

```bash
# Enroll in TOTP MFA (requires authentication)
curl -k -X POST https://localhost:8443/api/v1/auth/mfa/enroll \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "method": "totp",
    "device_name": "My Authenticator"
  }'

# Response includes:
# - "secret": Your TOTP secret (base32)
# - "qr_code_uri": otpauth:// URI for QR code generation

# Scan the QR code with Google Authenticator, Authy, or similar

# Test login with MFA
curl -k -X POST https://localhost:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "YourSecurePassword123!",
    "mfa_token": "123456"
  }'
```

**Note**: 
- ✅ TOTP (Time-based One-Time Password) is fully implemented
- ❌ WebAuthn/FIDO2 returns 501 Not Implemented
- ❌ SMS MFA returns 501 Not Implemented

---

## Issue Client Certificate (✅ Works)

For mTLS authentication:

```bash
# Issue client certificate
docker-compose exec ztdc python manage.py issue-certificate \
  --username admin \
  --output-dir /app/client-certs

# Certificates saved to ./client-certs/ on host
# Files created:
# - admin.crt (certificate)
# - admin.key (private key)

# Use with curl:
curl --cert ./client-certs/admin.crt \
     --key ./client-certs/admin.key \
     -k https://localhost:8443/api/v1/endpoint
```

**Note**: Certificate generation works, but mTLS enforcement is not yet enabled by default.

---

## View Metrics (✅ Works)

```bash
# Prometheus metrics endpoint
curl -k https://localhost:8443/metrics

# Grafana dashboards
# 1. Open http://localhost:3000
# 2. Login: admin / admin
# 3. Navigate to Dashboards → Zero-Trust Controller
```

---

## Stopping Services

```bash
# Stop all services
docker-compose down

# Stop and remove volumes (WARNING: deletes data)
docker-compose down -v

# Stop and keep data
docker-compose stop
```

---

## Troubleshooting

### Services won't start

```bash
# Check logs
docker-compose logs

# Check specific service
docker-compose logs ztdc
docker-compose logs postgres
docker-compose logs redis

# Restart a service
docker-compose restart ztdc
```

### Database connection issues

```bash
# Test database connection
docker-compose exec postgres psql -U ztdc -d ztdc -c "SELECT 1;"

# Check if tables exist
docker-compose exec postgres psql -U ztdc -d ztdc -c "\\dt"

# Re-initialize database
docker-compose exec ztdc python manage.py init-domain
```

### Authentication fails

```bash
# Check audit logs
docker-compose exec ztdc cat /app/logs/audit.log

# Check user exists
docker-compose exec postgres psql -U ztdc -d ztdc \
  -c "SELECT username, enabled, account_locked FROM users;"

# Check failed attempts
docker-compose exec postgres psql -U ztdc -d ztdc \
  -c "SELECT username, failed_attempts, locked_until FROM users WHERE username='admin';"
```

### Certificate issues

```bash
# Check if CA exists
docker-compose exec ztdc ls -la /app/ca/

# Regenerate CA and certificates
docker-compose exec ztdc rm -rf /app/ca/* /app/certs/*
docker-compose exec ztdc python manage.py init-domain
docker-compose restart ztdc
```

### Port already in use

```bash
# Check what's using port 8443
lsof -i :8443

# Change port in docker-compose.yml:
# ports:
#   - "9443:8443"  # Use 9443 instead
```

### Startup fails with security errors

If you see errors like "CRITICAL: ALLOWED_ORIGINS contains '*' in production":

```bash
# Edit .env and set specific origins
ENVIRONMENT=development  # For testing
ALLOWED_ORIGINS=https://yourdomain.com,http://localhost:3000
ALLOWED_HOSTS=yourdomain.com,localhost

# Restart
docker-compose restart ztdc
```

---

## Next Steps

1. **Read Status**: [PROJECT_STATUS.md](PROJECT_STATUS.md) - Understand what's implemented
2. **Production Deployment**: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) - Kubernetes guide
3. **Architecture**: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - System design
4. **Security**: [SECURITY.md](SECURITY.md) - Security best practices
5. **Contributing**: [CONTRIBUTING.md](CONTRIBUTING.md) - Help improve this project

---

## Configuration Options

Key environment variables in `.env`:

| Variable | Description | Default | Status |
|----------|-------------|---------|--------|
| `DOMAIN_NAME` | Your domain | example.com | ✅ |
| `ENVIRONMENT` | Environment mode | development | ✅ |
| `ALLOWED_ORIGINS` | CORS origins | `*` (dev), `[]` (prod) | ✅ |
| `MFA_REQUIRED` | Require MFA | false | ⚠️ Checked but not enforced |
| `MTLS_REQUIRED` | Require mTLS | false | ❌ Not enforced |
| `DEVICE_TRUST_REQUIRED` | Require trusted devices | false | ❌ Not implemented |
| `CONTINUOUS_AUTH_INTERVAL` | Re-auth interval (sec) | 3600 | ⚠️ Configured, not enforced |
| `PASSWORD_MIN_LENGTH` | Min password length | 12 | ✅ |
| `OIDC_ENABLED` | Enable OIDC | true | ⚠️ Stub only |
| `SAML_ENABLED` | Enable SAML | true | ⚠️ Stub only |

See `.env.example` for complete list and [PROJECT_STATUS.md](PROJECT_STATUS.md) for implementation status.

---

## Known Limitations

### ✅ What Works
- FastAPI application and API framework
- Database models and migrations
- Authentication with real database verification
- Password hashing with Argon2
- JWT token generation and verification
- TOTP MFA enrollment and verification
- Account lockout after failed attempts
- Audit logging to database and file
- Certificate Authority and certificate generation
- Prometheus metrics
- Kubernetes deployment manifests

### ⚠️ Partially Implemented
- Session management (basic persistence)
- Risk scoring (algorithm exists, limited data)
- MFA integration (TOTP only)

### ❌ Not Yet Implemented
- OIDC/OAuth2 token flows (endpoints return 501)
- SAML SSO/ACS (stub only)
- ABAC policy evaluation engine
- Device trust workflows
- LDAP directory service
- WebAuthn/FIDO2 MFA
- SMS MFA
- Rate limiting
- OpenTelemetry tracing
- Admin UI
- Full test suite

See [PROJECT_STATUS.md](PROJECT_STATUS.md) for detailed roadmap.

---

## Support & Feedback

- **Issues**: [GitHub Issues](https://github.com/chad-atexpedient/zero-trust-domain-controller/issues)
- **Status**: [PROJECT_STATUS.md](PROJECT_STATUS.md)
- **Fixes**: [FIXES_APPLIED.md](FIXES_APPLIED.md)
- **Security**: Report vulnerabilities per [SECURITY.md](SECURITY.md)

---

**🎉 You now have a running Zero-Trust Domain Controller demo!**

Remember: This is a prototype. See [PROJECT_STATUS.md](PROJECT_STATUS.md) before deploying anywhere.
