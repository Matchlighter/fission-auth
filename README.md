# Fission Auth Microservice

A Crystal-based forward authentication microservice for Fission FaaS functions. Validates incoming requests based on CRD-defined access rules and pod metadata from the pod-watcher service.

## Features

- **Forward Auth Pattern**: Works as a forward authentication endpoint (e.g., with Traefik/Nginx)
- **CRD-Based Rules**: Access control rules defined as Kubernetes Custom Resources
- **Pod-Aware**: Queries pod-watcher to identify source pods by IP
- **Pattern Matching**: Supports wildcards in function names
- **Namespace Isolation**: Default deny for cross-namespace calls unless explicitly allowed
- **External Access Control**: Can allow/deny external (non-cluster) requests
- **Label Requirements**: Can require specific labels on calling pods
- **High Performance**: Crystal binary with ~5-15 MB memory footprint

## Architecture

```
Ingress/Gateway → Fission Auth (forward_auth) → Fission Router → Function
                         ↓
                   Pod Watcher Service
                         ↓
                   Kubernetes API
```

## CRD: FunctionAccessRule

Access rules are defined per-namespace and control which callers can invoke functions. The design follows Kubernetes NetworkPolicy patterns for familiar, powerful access control.

### Fields

- `targetFunction` (string, required): Function name or pattern (* for all, prefix*, *suffix)
- `from` (array): List of allowed sources using NetworkPolicy-style peer selectors
  - `ipBlock`: CIDR-based IP allowlist (for external requests)
    - `cidr`: IP range (e.g., "203.0.113.0/24")
    - `except`: List of excluded IPs within the CIDR
  - `namespaceSelector`: Select namespaces by labels
    - `matchLabels`: Key-value label pairs
    - `matchExpressions`: Advanced label matching with operators
  - `podSelector`: Select pods by labels
    - `matchLabels`: Key-value label pairs
    - `matchExpressions`: Advanced label matching with operators

### Examples

Allow same-namespace calls (using namespace selector):
```yaml
apiVersion: fission.io/v1
kind: FunctionAccessRule
metadata:
  name: allow-same-namespace
  namespace: default
spec:
  targetFunction: "*"
  from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: default
```

Allow cross-namespace for monitoring (namespace selector):
```yaml
apiVersion: fission.io/v1
kind: FunctionAccessRule
metadata:
  name: allow-monitoring
  namespace: default
spec:
  targetFunction: "metrics-*"
  from:
    - namespaceSelector:
        matchExpressions:
          - key: environment
            operator: In
            values:
              - production
              - staging
```

Allow specific pods with labels:
```yaml
apiVersion: fission.io/v1
kind: FunctionAccessRule
metadata:
  name: allow-backend-pods
  namespace: default
spec:
  targetFunction: "internal-*"
  from:
    - podSelector:
        matchLabels:
          app: backend
          role: api
```

Allow external access from specific IP range:
```yaml
apiVersion: fission.io/v1
kind: FunctionAccessRule
metadata:
  name: public-api
  namespace: default
spec:
  targetFunction: "public-*"
  from:
    - ipBlock:
        cidr: 0.0.0.0/0  # Allow all external IPs
        except:
          - 10.0.0.0/8    # Except internal ranges
          - 172.16.0.0/12
          - 192.168.0.0/16
```

Combined namespace and pod selectors:
```yaml
apiVersion: fission.io/v1
kind: FunctionAccessRule
metadata:
  name: admin-access
  namespace: admin
spec:
  targetFunction: "admin-*"
  from:
    - namespaceSelector:
        matchLabels:
          security: privileged
      podSelector:
        matchLabels:
          role: admin
```

## Configuration

Environment variables:
- `PORT` - HTTP server port (default: 8080)
- `HOST` - HTTP server host (default: 0.0.0.0)
- `POD_WATCHER_URL` - URL of pod-watcher service (default: http://pod-watcher.pod-watcher.svc.cluster.local:8080)

## API

### Forward Auth Check
**Any Method** `/auth` (or any path)

Headers:
- `X-Real-IP` - Source IP address (required)
- `X-Original-URI` - Original request path (used to determine target function)

Response:
- `200` - Authorized (with X-Source-* headers)
- `403` - Forbidden

Response Headers:
- `X-Source-Namespace` - Source pod namespace
- `X-Source-Pod` - Source pod name
- `X-Source-Type` - "cluster" or "external"

### Health Check
**GET** `/health`

### Readiness Check
**GET** `/ready`

## Building

```bash
chmod +x build.sh
./build.sh
```

## Running Locally

```bash
# Requires access to Kubernetes API and pod-watcher service
export POD_WATCHER_URL=http://localhost:8080
./fission-auth
```

## Deployment

### 1. Install the CRD
```bash
kubectl apply -f k8s/crd-functionaccessrule.yaml
```

### 2. Build and push Docker image
```bash
docker build -t your-registry/fission-auth:latest .
docker push your-registry/fission-auth:latest
```

### 3. Deploy to Kubernetes
```bash
kubectl apply -f k8s/
```

### 4. Configure your Ingress/Gateway

#### Traefik Example
```yaml
apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
metadata:
  name: fission-auth
  namespace: fission
spec:
  forwardAuth:
    address: http://fission-auth.fission-auth.svc.cluster.local:8080
    trustForwardHeader: true
```

#### Nginx Ingress Example
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: fission
  annotations:
    nginx.ingress.kubernetes.io/auth-url: "http://fission-auth.fission-auth.svc.cluster.local:8080"
    nginx.ingress.kubernetes.io/auth-response-headers: "X-Source-Namespace,X-Source-Pod,X-Source-Type"
```

## Default Behavior

When no rules are defined for a namespace:
- Same-namespace calls: **Allowed**
- Cross-namespace calls: **Denied**
- External calls: **Denied**

When rules exist but don't match the target function:
- Same-namespace calls: **Allowed**
- Cross-namespace calls: **Denied**
- External calls: **Denied**

## Authorization Logic

1. Extract source IP from `X-Real-IP` header
2. Query pod-watcher to get pod metadata (if any)
3. Extract target function and namespace from request path
4. Fetch access rules for target namespace
5. Evaluate rules in order:
   - Check deny list
   - Check required labels
   - Check allowed namespaces
6. Default to same-namespace allowed, cross-namespace denied

## Performance

- Memory: ~5-15 MB per instance
- Startup: <100ms
- Request latency: <10ms (cached rules)
- Rules cache TTL: 30 seconds

## Dependencies

- `jgaskins/kubernetes` - Kubernetes client with CRD support
- Crystal stdlib (HTTP, JSON, Log)
