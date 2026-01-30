# Quick Start Guide

Get your Zero-Trust Domain Controller running in 5 minutes!

## Prerequisites

- Docker 24.0+
- Docker Compose 2.0+
- 4GB RAM minimum
- Port 8443 available

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

# Generate secure keys (IMPORTANT!)
python3 << 'EOF'
import secrets
print(f"JWT_SECRET_KEY={secrets.token_urlsafe(32)}")
print(f"ENCRYPTION_KEY={secrets.token_urlsafe(32)}")
print(f"CA_PASSPHRASE={secrets.token_urlsafe(32)}")
print(f"POSTGRES_PASSWORD={secrets.token_urlsafe(16)}")
print(f"REDIS_PASSWORD={secrets.token_urlsafe(16)}")
EOF

# Update .env file with the generated values above
```

### 3. Start Services

```bash
# Start all services
docker-compose up -d

# Wait for services to be ready (30-60 seconds)
docker-compose ps
```

### 4. Initialize Domain Controller

```bash
# Initialize the domain (creates database, CA, certificates)
docker-compose exec ztdc python manage.py init-domain

# Create an admin user
docker-compose exec ztdc python manage.py create-admin \
  --username admin \
  --email admin@example.com \
  --password 'YourSecurePassword123!'
```

### 5. Verify Installation

```bash
# Check health
curl -k https://localhost:8443/health

# Expected output:
# {"status":"healthy","service":"zero-trust-domain-controller","version":"1.0.0"}

# View logs
docker-compose logs -f ztdc
```

## Access Points

Once running, you can access:

| Service | URL | Credentials |
|---------|-----|-------------|
| **API** | https://localhost:8443 | Bearer token |
| **API Docs** | https://localhost:8443/api/docs | N/A |
| **OIDC Discovery** | https://localhost:8443/.well-known/openid-configuration | N/A |
| **Grafana** | http://localhost:3000 | admin/admin |
| **Prometheus** | http://localhost:9090 | N/A |

## First API Call

### 1. Login

```bash
curl -k -X POST https://localhost:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "YourSecurePassword123!"
  }'
```

### 2. Create a User

```bash
# Save the access_token from login response
TOKEN="your-access-token-here"

curl -k -X POST https://localhost:8443/api/v1/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john.doe",
    "email": "john.doe@example.com",
    "password": "SecurePassword123!",
    "first_name": "John",
    "last_name": "Doe",
    "groups": ["users"],
    "mfa_required": true
  }'
```

### 3. Create an Access Policy

```bash
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
    "conditions": {
      "mfa_verified": true
    },
    "priority": 100
  }'
```

## Testing MFA

### Enable TOTP

```bash
# Enroll in TOTP MFA
curl -k -X POST https://localhost:8443/api/v1/auth/mfa/enroll \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "method": "totp"
  }'

# Response includes:
# - "secret": Your TOTP secret
# - "qr_code_uri": Scan with authenticator app

# Test login with MFA
curl -k -X POST https://localhost:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "YourSecurePassword123!",
    "mfa_token": "123456"
  }'
```

## Issue Client Certificate

For mTLS authentication:

```bash
# Issue client certificate
docker-compose exec ztdc python manage.py issue-certificate \
  --username admin

# Certificates saved to ./client-certs/
# Use with: curl --cert admin.crt --key admin.key
```

## View Metrics

```bash
# Prometheus metrics
curl -k https://localhost:8443/metrics

# View in Grafana
# 1. Open http://localhost:3000
# 2. Login with admin/admin
# 3. Navigate to Dashboards
```

## Stopping Services

```bash
# Stop all services
docker-compose down

# Stop and remove volumes (WARNING: deletes data)
docker-compose down -v
```

## Troubleshooting

### Services won't start

```bash
# Check logs
docker-compose logs

# Check specific service
docker-compose logs ztdc
docker-compose logs postgres
docker-compose logs redis
```

### Database connection issues

```bash
# Test database connection
docker-compose exec postgres psql -U ztdc -d ztdc -c "SELECT 1;"
```

### Certificate issues

```bash
# Regenerate certificates
docker-compose exec ztdc rm -rf /app/certs/*
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

## Next Steps

1. **Production Deployment**: See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)
2. **Architecture**: See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
3. **Security**: See [SECURITY.md](SECURITY.md)
4. **Contributing**: See [CONTRIBUTING.md](CONTRIBUTING.md)

## Configuration Options

Key environment variables in `.env`:

| Variable | Description | Default |
|----------|-------------|---------|
| `DOMAIN_NAME` | Your domain | example.com |
| `MFA_REQUIRED` | Require MFA | true |
| `MTLS_REQUIRED` | Require mTLS | false |
| `DEVICE_TRUST_REQUIRED` | Require trusted devices | false |
| `CONTINUOUS_AUTH_INTERVAL` | Re-auth interval (seconds) | 3600 |
| `PASSWORD_MIN_LENGTH` | Minimum password length | 12 |
| `OIDC_ENABLED` | Enable OIDC | true |
| `SAML_ENABLED` | Enable SAML | true |

See `.env.example` for complete list.

## Common Use Cases

### SSO with OIDC

```bash
# Get OIDC configuration
curl -k https://localhost:8443/.well-known/openid-configuration

# Configure your application with:
# - Issuer: https://localhost:8443
# - Authorization endpoint: https://localhost:8443/oauth2/authorize
# - Token endpoint: https://localhost:8443/oauth2/token
```

### Enterprise SAML Integration

```bash
# Get SAML metadata
curl -k https://localhost:8443/saml/metadata > metadata.xml

# Import metadata.xml into your IdP (Okta, Azure AD, etc.)
```

### Zero-Trust Access

```bash
# Request requires:
# 1. Valid JWT token
# 2. MFA verification
# 3. Trusted device (if enabled)
# 4. Policy authorization
# 5. Risk score below threshold

curl -k https://localhost:8443/api/v1/resource \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Device-ID: device-12345"
```

## Support

- **Issues**: [GitHub Issues](https://github.com/chad-atexpedient/zero-trust-domain-controller/issues)
- **Documentation**: [docs/](docs/)
- **Security**: security@example.com

---

**🎉 Congratulations!** You now have a running Zero-Trust Domain Controller!
