# Deployment Guide

This guide covers deploying the Zero-Trust Domain Controller in various environments.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Local Development](#local-development)
- [Docker Deployment](#docker-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Cloud Platform Deployment](#cloud-platform-deployment)
- [Production Considerations](#production-considerations)

## Prerequisites

### System Requirements

- **CPU**: 2+ cores (4+ recommended for production)
- **RAM**: 4GB minimum (8GB+ recommended for production)
- **Storage**: 20GB minimum (SSD recommended)
- **OS**: Linux (Ubuntu 20.04+, RHEL 8+, etc.)

### Software Requirements

- Docker 24.0+
- Docker Compose 2.0+ (for local development)
- Kubernetes 1.25+ (for K8s deployment)
- kubectl CLI
- Python 3.11+ (for local development)

## Local Development

### Quick Start

```bash
# Clone repository
git clone https://github.com/chad-atexpedient/zero-trust-domain-controller.git
cd zero-trust-domain-controller

# Copy environment file
cp .env.example .env

# Generate secure keys
export JWT_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
export ENCRYPTION_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
export CA_PASSPHRASE=$(python -c "import secrets; print(secrets.token_urlsafe(32))")

# Update .env with generated keys
sed -i "s/JWT_SECRET_KEY=.*/JWT_SECRET_KEY=$JWT_SECRET/" .env
sed -i "s/ENCRYPTION_KEY=.*/ENCRYPTION_KEY=$ENCRYPTION_KEY/" .env
sed -i "s/CA_PASSPHRASE=.*/CA_PASSPHRASE=$CA_PASSPHRASE/" .env

# Start services
docker-compose up -d

# Initialize domain
docker-compose exec ztdc python manage.py init-domain

# Create admin user
docker-compose exec ztdc python manage.py create-admin
```

### Accessing Services

- **API**: https://localhost:8443
- **Grafana**: http://localhost:3000 (admin/admin)
- **Prometheus**: http://localhost:9090

## Docker Deployment

### Build Custom Image

```bash
# Build image
docker build -t ztdc:latest .

# Tag for registry
docker tag ztdc:latest your-registry.com/ztdc:1.0.0

# Push to registry
docker push your-registry.com/ztdc:1.0.0
```

### Docker Compose Production

```yaml
# docker-compose.prod.yml
version: '3.9'

services:
  ztdc:
    image: your-registry.com/ztdc:1.0.0
    restart: unless-stopped
    environment:
      - MTLS_REQUIRED=true
      - MFA_REQUIRED=true
    volumes:
      - ./certs:/app/certs:ro
      - ./logs:/app/logs
    ports:
      - "443:8443"
    depends_on:
      - postgres
      - redis
```

## Kubernetes Deployment

### Prerequisites

```bash
# Verify cluster access
kubectl cluster-info

# Install cert-manager (for TLS certificates)
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml
```

### Step 1: Create Namespace

```bash
kubectl apply -f k8s/namespace.yaml
```

### Step 2: Configure Secrets

**IMPORTANT**: Generate unique secrets for production!

```bash
# Generate secrets
export JWT_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
export ENCRYPTION_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
export CA_PASSPHRASE=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
export POSTGRES_PASSWORD=$(python -c "import secrets; print(secrets.token_urlsafe(16))")
export REDIS_PASSWORD=$(python -c "import secrets; print(secrets.token_urlsafe(16))")

# Create secrets
kubectl create secret generic ztdc-secrets -n zero-trust \
  --from-literal=JWT_SECRET_KEY=$JWT_SECRET \
  --from-literal=ENCRYPTION_KEY=$ENCRYPTION_KEY \
  --from-literal=CA_PASSPHRASE=$CA_PASSPHRASE \
  --from-literal=POSTGRES_PASSWORD=$POSTGRES_PASSWORD \
  --from-literal=REDIS_PASSWORD=$REDIS_PASSWORD \
  --from-literal=DATABASE_URL="postgresql://ztdc:$POSTGRES_PASSWORD@postgres:5432/ztdc" \
  --from-literal=REDIS_URL="redis://:$REDIS_PASSWORD@redis:6379/0"

# Create Postgres secret
kubectl create secret generic postgres-secret -n zero-trust \
  --from-literal=POSTGRES_DB=ztdc \
  --from-literal=POSTGRES_USER=ztdc \
  --from-literal=POSTGRES_PASSWORD=$POSTGRES_PASSWORD
```

### Step 3: Update ConfigMap

```bash
# Edit k8s/configmap.yaml with your domain
vim k8s/configmap.yaml

# Apply configmap
kubectl apply -f k8s/configmap.yaml
```

### Step 4: Deploy Database

```bash
# Deploy PostgreSQL
kubectl apply -f k8s/postgres-deployment.yaml

# Wait for PostgreSQL to be ready
kubectl wait --for=condition=ready pod -l app=postgres -n zero-trust --timeout=120s

# Deploy Redis
kubectl apply -f k8s/redis-deployment.yaml

# Wait for Redis to be ready
kubectl wait --for=condition=ready pod -l app=redis -n zero-trust --timeout=120s
```

### Step 5: Deploy Application

```bash
# Update deployment with your image
vim k8s/deployment.yaml
# Change: image: ztdc:latest
# To:     image: your-registry.com/ztdc:1.0.0

# Deploy application
kubectl apply -f k8s/deployment.yaml

# Wait for deployment
kubectl wait --for=condition=available deployment/ztdc -n zero-trust --timeout=300s
```

### Step 6: Configure Ingress

```bash
# Update ingress with your domain
vim k8s/ingress.yaml
# Change: host: ztdc.example.com
# To:     host: ztdc.yourdomain.com

# Apply ingress
kubectl apply -f k8s/ingress.yaml

# Apply service
kubectl apply -f k8s/service.yaml
```

### Step 7: Enable Auto-scaling

```bash
# Deploy HPA
kubectl apply -f k8s/hpa.yaml

# Verify HPA
kubectl get hpa -n zero-trust
```

### Step 8: Initialize Domain

```bash
# Get pod name
POD=$(kubectl get pod -n zero-trust -l app=ztdc -o jsonpath="{.items[0].metadata.name}")

# Initialize domain
kubectl exec -n zero-trust $POD -- python manage.py init-domain

# Create admin user
kubectl exec -it -n zero-trust $POD -- python manage.py create-admin
```

## Cloud Platform Deployment

### AWS EKS

```bash
# Create EKS cluster
eksctl create cluster \
  --name ztdc-cluster \
  --region us-west-2 \
  --nodegroup-name standard-workers \
  --node-type t3.medium \
  --nodes 3 \
  --nodes-min 3 \
  --nodes-max 10 \
  --managed

# Install AWS Load Balancer Controller
kubectl apply -k "github.com/aws/eks-charts/stable/aws-load-balancer-controller//crds"

# Deploy application
kubectl apply -f k8s/

# Get load balancer URL
kubectl get svc ztdc -n zero-trust -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'
```

### Google GKE

```bash
# Create GKE cluster
gcloud container clusters create ztdc-cluster \
  --num-nodes=3 \
  --machine-type=n1-standard-2 \
  --region=us-central1

# Get credentials
gcloud container clusters get-credentials ztdc-cluster --region=us-central1

# Deploy application
kubectl apply -f k8s/

# Get load balancer IP
kubectl get svc ztdc -n zero-trust -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
```

### Azure AKS

```bash
# Create resource group
az group create --name ztdc-rg --location eastus

# Create AKS cluster
az aks create \
  --resource-group ztdc-rg \
  --name ztdc-cluster \
  --node-count 3 \
  --node-vm-size Standard_D2s_v3 \
  --enable-managed-identity

# Get credentials
az aks get-credentials --resource-group ztdc-rg --name ztdc-cluster

# Deploy application
kubectl apply -f k8s/
```

## Production Considerations

### Security

1. **Secrets Management**
   - Use HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault
   - Never commit secrets to Git
   - Rotate secrets regularly

2. **Network Security**
   - Enable network policies
   - Use private subnets for databases
   - Implement WAF (Web Application Firewall)
   - Enable DDoS protection

3. **TLS/mTLS**
   - Use valid certificates from trusted CA
   - Enable mTLS for service-to-service
   - Implement certificate rotation

### High Availability

1. **Multi-Zone Deployment**
   ```yaml
   affinity:
     podAntiAffinity:
       requiredDuringSchedulingIgnoredDuringExecution:
       - labelSelector:
           matchExpressions:
           - key: app
             operator: In
             values:
             - ztdc
         topologyKey: topology.kubernetes.io/zone
   ```

2. **Database HA**
   - Use managed database services (RDS, Cloud SQL)
   - Enable read replicas
   - Automated backups
   - Point-in-time recovery

3. **Redis HA**
   - Redis Sentinel or Cluster mode
   - Managed Redis (ElastiCache, MemoryStore)

### Performance

1. **Resource Limits**
   ```yaml
   resources:
     requests:
       memory: "512Mi"
       cpu: "250m"
     limits:
       memory: "2Gi"
       cpu: "1000m"
   ```

2. **Horizontal Scaling**
   - Configure HPA based on metrics
   - Set appropriate min/max replicas
   - Use custom metrics if needed

3. **Caching**
   - Enable Redis caching
   - Configure appropriate TTLs
   - Monitor cache hit rates

### Monitoring

1. **Metrics**
   - Deploy Prometheus and Grafana
   - Set up custom dashboards
   - Configure alerts

2. **Logging**
   - Centralized logging (ELK, Splunk, CloudWatch)
   - Structured JSON logs
   - Log retention policies

3. **Tracing**
   - Distributed tracing (Jaeger, Zipkin)
   - Request correlation IDs
   - Performance profiling

### Backup & Recovery

1. **Database Backups**
   ```bash
   # Automated backup script
   kubectl exec -n zero-trust postgres-0 -- \
     pg_dump -U ztdc ztdc | \
     gzip > backup-$(date +%Y%m%d).sql.gz
   ```

2. **Certificate Backups**
   - Backup CA certificates securely
   - Store in encrypted storage
   - Document recovery procedures

3. **Disaster Recovery**
   - Document RTO/RPO requirements
   - Test recovery procedures
   - Maintain DR environment

### Compliance

1. **Audit Logging**
   - Enable comprehensive audit logs
   - Immutable log storage
   - Regular log reviews

2. **Compliance Controls**
   - SOC 2, HIPAA, PCI DSS controls
   - Regular compliance audits
   - Document security controls

## Troubleshooting

### Common Issues

1. **Pods not starting**
   ```bash
   kubectl describe pod <pod-name> -n zero-trust
   kubectl logs <pod-name> -n zero-trust
   ```

2. **Database connection issues**
   ```bash
   kubectl exec -it -n zero-trust <pod-name> -- \
     psql $DATABASE_URL
   ```

3. **Certificate issues**
   ```bash
   kubectl exec -it -n zero-trust <pod-name> -- \
     python manage.py health-check
   ```

## Support

- Documentation: [docs/](./)
- Issues: [GitHub Issues](https://github.com/chad-atexpedient/zero-trust-domain-controller/issues)
- Security: security@example.com