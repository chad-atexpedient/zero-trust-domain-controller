# Architecture Documentation

## Overview

The Zero-Trust Domain Controller is built on a microservices-inspired architecture with a focus on security, scalability, and maintainability.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Internet / Users                         │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         │ HTTPS/TLS
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Load Balancer / Ingress                     │
│                    (HAProxy / NGINX / ALB)                       │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         │ mTLS (Optional)
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    API Gateway / Rate Limiter                    │
│                      (Built into FastAPI)                        │
└───────────┬──────────────────────┬─────────────────┬────────────┘
            │                      │                 │
            ▼                      ▼                 ▼
┌───────────────────┐  ┌─────────────────┐  ┌──────────────────┐
│  Authentication   │  │   Policy        │  │  Certificate     │
│  Service          │  │   Engine        │  │  Authority       │
│                   │  │   (ABAC)        │  │  (PKI)           │
│ - OAuth2/OIDC     │  │                 │  │                  │
│ - SAML 2.0        │  │ - Policy Eval   │  │ - Issue Certs    │
│ - JWT Tokens      │  │ - Risk Scoring  │  │ - Revocation     │
│ - MFA/TOTP        │  │ - Decision      │  │ - CRL/OCSP       │
└─────────┬─────────┘  └────────┬────────┘  └────────┬─────────┘
          │                     │                      │
          └─────────────────────┼──────────────────────┘
                                │
                                ▼
                ┌───────────────────────────┐
                │   Directory Service       │
                │   (LDAP Compatible)       │
                │                           │
                │ - Users & Groups          │
                │ - Attributes              │
                │ - Organizational Units    │
                └────────────┬──────────────┘
                             │
                             ▼
        ┌────────────────────────────────────────┐
        │         Data Layer                     │
        │                                        │
        │  ┌──────────────┐  ┌───────────────┐  │
        │  │  PostgreSQL  │  │   Redis       │  │
        │  │              │  │               │  │
        │  │ - Users      │  │ - Sessions    │  │
        │  │ - Policies   │  │ - Cache       │  │
        │  │ - Audit Logs │  │ - Rate Limit  │  │
        │  │ - Certs      │  │ - Locks       │  │
        │  └──────────────┘  └───────────────┘  │
        └────────────────────────────────────────┘

        ┌────────────────────────────────────────┐
        │         Observability                  │
        │                                        │
        │  ┌──────────────┐  ┌───────────────┐  │
        │  │  Prometheus  │  │   Grafana     │  │
        │  │  (Metrics)   │  │  (Dashboards) │  │
        │  └──────────────┘  └───────────────┘  │
        │                                        │
        │  ┌──────────────────────────────────┐ │
        │  │   Structured Logging (JSON)      │ │
        │  │   ELK / Splunk / CloudWatch      │ │
        │  └──────────────────────────────────┘ │
        └────────────────────────────────────────┘
```

## Component Details

### 1. API Gateway

**Technology**: FastAPI

**Responsibilities**:
- Request routing
- Input validation
- Rate limiting
- CORS handling
- Request/response logging

**Endpoints**:
- `/api/v1/auth/*` - Authentication
- `/api/v1/users/*` - User management
- `/api/v1/policies/*` - Policy management
- `/api/v1/oidc/*` - OpenID Connect
- `/api/v1/saml/*` - SAML 2.0
- `/health` - Health check
- `/metrics` - Prometheus metrics

### 2. Authentication Service

**Technology**: Python with PyJWT, Passlib, PyOTP

**Features**:
- **Password Authentication**: Argon2 hashing
- **MFA Support**: TOTP, WebAuthn, SMS
- **OAuth 2.0/OIDC**: Standard compliant
- **SAML 2.0**: Enterprise SSO
- **JWT Tokens**: Access and refresh tokens
- **Session Management**: Stateless with Redis backup

**Security**:
- Password strength validation
- Account lockout after failed attempts
- Suspicious activity detection
- Device fingerprinting
- IP-based geolocation

### 3. Policy Engine

**Technology**: Attribute-Based Access Control (ABAC)

**Policy Structure**:
```json
{
  "name": "developer-api-access",
  "effect": "allow",
  "principals": ["group:developers"],
  "resources": ["service:api:*"],
  "actions": ["read", "write"],
  "conditions": {
    "device_trusted": true,
    "mfa_verified": true,
    "time_of_day": "09:00-17:00",
    "ip_range": "10.0.0.0/8"
  }
}
```

**Evaluation Flow**:
1. Extract request context
2. Identify applicable policies
3. Evaluate conditions
4. Apply priority ordering
5. Return decision (allow/deny)

**Performance**:
- Policy caching in Redis
- Compiled policy evaluation
- Sub-millisecond decisions

### 4. Certificate Authority

**Technology**: Python Cryptography library

**Capabilities**:
- Root CA generation
- Server certificate issuance
- Client certificate issuance
- Certificate revocation (CRL)
- OCSP responder support

**Certificate Types**:
- **Root CA**: 10-year validity
- **Server Certs**: 1-year validity
- **Client Certs**: 1-year validity
- **Device Certs**: 90-day validity

**PKI Hierarchy**:
```
Root CA (self-signed)
  └── Intermediate CA (optional)
        ├── Server Certificates
        └── Client Certificates
              └── Device Certificates
```

### 5. Directory Service

**Technology**: LDAP-compatible interface

**Schema**:
```
dc=example,dc=com
  ├── ou=users
  │     ├── uid=john.doe
  │     └── uid=jane.smith
  ├── ou=groups
  │     ├── cn=admins
  │     ├── cn=developers
  │     └── cn=users
  └── ou=devices
        ├── cn=device-001
        └── cn=device-002
```

**Supported Operations**:
- Bind (authentication)
- Search
- Add
- Modify
- Delete
- Compare

### 6. Data Layer

#### PostgreSQL

**Tables**:
- `users` - User accounts
- `groups` - User groups
- `user_groups` - Membership
- `mfa_secrets` - MFA configurations
- `devices` - Registered devices
- `policies` - Access policies
- `sessions` - Active sessions
- `audit_log` - Security events
- `certificates` - Issued certificates
- `oauth_clients` - OAuth clients

**Indexes**:
- Username, email (unique)
- Session token
- Audit log timestamp
- Certificate serial number

#### Redis

**Use Cases**:
- Session storage
- Policy cache
- Rate limiting counters
- Distributed locks
- Temporary MFA tokens
- Password reset tokens

## Zero-Trust Principles

### 1. Verify Explicitly

**Implementation**:
```python
def authenticate_request(request):
    # 1. Verify JWT token
    token = verify_jwt(request.headers["Authorization"])
    
    # 2. Verify mTLS certificate (if enabled)
    if MTLS_REQUIRED:
        verify_client_certificate(request.client_cert)
    
    # 3. Verify device trust
    if DEVICE_TRUST_REQUIRED:
        verify_device_trust(token["device_id"])
    
    # 4. Calculate risk score
    risk_score = calculate_risk(
        user=token["sub"],
        ip=request.client.ip,
        device=token["device_id"],
        time=now(),
    )
    
    # 5. Check if re-authentication needed
    if risk_score > THRESHOLD:
        raise RequiresReauthentication()
    
    return token
```

### 2. Least Privilege

**Implementation**:
- Default deny policy
- Explicit allow policies
- Time-bound access
- Just-in-time provisioning
- Automatic access expiration

### 3. Assume Breach

**Implementation**:
- Encryption at rest
- Encryption in transit
- Micro-segmentation
- Anomaly detection
- Comprehensive audit logging
- Automated incident response

## Security Features

### Cryptography

- **TLS**: TLS 1.3 only
- **Key Exchange**: ECDHE
- **Cipher Suites**: AES-256-GCM, ChaCha20-Poly1305
- **Hashing**: SHA-256, SHA-384
- **Password Hashing**: Argon2id
- **Token Signing**: RS256, ES256

### Authentication Flow

```
┌──────┐                                    ┌──────────┐
│Client│                                    │   ZTDC   │
└───┬──┘                                    └────┬─────┘
    │                                            │
    │  1. POST /api/v1/auth/login               │
    │  {username, password}                     │
    ├──────────────────────────────────────────>│
    │                                            │
    │  2. Verify credentials                     │
    │     - Check password hash                  │
    │     - Check account status                 │
    │     - Check failed attempts                │
    │                                            │
    │  3. MFA Challenge (if enabled)             │
    │<───────────────────────────────────────────┤
    │  {mfa_required: true, methods: ["totp"]}  │
    │                                            │
    │  4. POST /api/v1/auth/login               │
    │  {username, password, mfa_token}          │
    ├──────────────────────────────────────────>│
    │                                            │
    │  5. Verify MFA                             │
    │     - Validate TOTP token                  │
    │     - Check replay                         │
    │                                            │
    │  6. Calculate Risk Score                   │
    │     - IP reputation                        │
    │     - Device trust                         │
    │     - Time of day                          │
    │     - Location                             │
    │                                            │
    │  7. Issue Tokens                           │
    │<───────────────────────────────────────────┤
    │  {access_token, refresh_token}            │
    │                                            │
```

### Authorization Flow

```
┌──────┐                                    ┌──────────┐
│Client│                                    │   ZTDC   │
└───┬──┘                                    └────┬─────┘
    │                                            │
    │  1. GET /api/v1/resource                  │
    │  Authorization: Bearer <token>            │
    ├──────────────────────────────────────────>│
    │                                            │
    │  2. Verify Token                           │
    │     - Signature validation                 │
    │     - Expiration check                     │
    │     - Revocation check                     │
    │                                            │
    │  3. Extract Context                        │
    │     - User/principal                       │
    │     - Resource/action                      │
    │     - Environment (IP, time, device)       │
    │                                            │
    │  4. Evaluate Policies                      │
    │     - Load applicable policies             │
    │     - Evaluate conditions                  │
    │     - Apply precedence rules               │
    │                                            │
    │  5. Decision: ALLOW or DENY                │
    │                                            │
    │  6. Audit Log                              │
    │     - Record decision                      │
    │     - Store context                        │
    │                                            │
    │  7. Return Response                        │
    │<───────────────────────────────────────────┤
    │  200 OK or 403 Forbidden                  │
    │                                            │
```

## Scalability

### Horizontal Scaling

- Stateless application design
- Session state in Redis
- Database connection pooling
- Load balancing across replicas

### Performance Optimization

- **Caching**: Redis for policies, sessions
- **Database**: Connection pooling, indexes
- **API**: Async/await with FastAPI
- **CDN**: Static assets (if applicable)

### Resource Management

```yaml
resources:
  requests:
    cpu: 250m
    memory: 512Mi
  limits:
    cpu: 1000m
    memory: 2Gi
```

## Monitoring & Observability

### Metrics

- Request rate and latency
- Authentication success/failure rate
- Policy evaluation time
- Database connection pool usage
- Redis cache hit rate
- Certificate expiration alerts

### Logging

- Structured JSON logs
- Correlation IDs
- Security event logging
- Audit trail
- Error tracking

### Tracing

- Distributed tracing with OpenTelemetry
- Request flow visualization
- Performance bottleneck identification

## Deployment Patterns

### Blue-Green Deployment

1. Deploy new version (green)
2. Run health checks
3. Gradually shift traffic
4. Monitor for issues
5. Rollback or complete switch

### Canary Deployment

1. Deploy to small percentage
2. Monitor metrics
3. Gradually increase traffic
4. Full rollout or rollback

## Disaster Recovery

### Backup Strategy

- **Database**: Daily snapshots, point-in-time recovery
- **Certificates**: Encrypted backup of CA keys
- **Configuration**: Version controlled
- **Logs**: Retained for 90 days

### Recovery Procedures

1. Database restore from backup
2. Certificate reissuance if needed
3. Configuration redeployment
4. Service validation
5. Log analysis

## Future Enhancements

- Machine learning-based anomaly detection
- Behavioral biometrics
- Hardware security module (HSM) integration
- Blockchain-based audit trail
- Advanced threat intelligence integration