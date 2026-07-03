# neoworks API on Kubernetes

Runs the real `cmd/api` server (GraphQL API + in-process OAuth) as a horizontally
scalable Deployment, in front of self-hosted, failover-capable SurrealDB and Redis.

- `overlays/dev/` — **fast dev target**: real API in kind, but single-node rocksdb
  SurrealDB + single Redis + MinIO, no operators, no secrets. Boots in ~30s.
- `base/` — HA target: TiKV-backed SurrealDB + Redis Sentinel (for failover testing).
- `overlays/prod/` — production patches (external S3, ingress/TLS, bigger resources,
  anti-affinity, higher autoscale ceiling).

## When to use which (dev tiers)

| Tier | Use it for | Command |
|------|------------|---------|
| **process-compose** (unchanged) | everyday inner loop — local binaries, fast reload | your existing `process-compose` + one background `kind` cluster so the provisioner has a target |
| **`overlays/dev`** | exercising the app *in-cluster* (probes, rollout, tenant provisioning) without HA weight | `kubectl apply -k deploy/k8s/overlays/dev` |
| **`base`** | testing SurrealDB / Redis failover | `kubectl apply -k deploy/k8s/base` (+ operators & secrets below) |

The code is backwards-compatible: with `REDIS_SENTINEL_ADDRS` and `AUTH_PRIVATE_KEY`
unset, the API uses a plain Redis client and the per-process key fallback — so
process-compose needs no changes. Note that `cmd/api` now provisions tenants only
via `kubectl`, so local client-DB creation needs a reachable kind cluster.

### Fast dev bring-up

```sh
cd apps/api
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dist/api ./cmd/api
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dist/migrate ./cmd/migrate
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dist/provisiondemo ./cmd/provisiondemo
docker build --provenance=false -f deploy/Dockerfile.demo -t neoworks-api:demo .
kind load docker-image neoworks-api:demo --name neoworks

kubectl apply -k deploy/k8s/overlays/dev
kubectl -n neoworks-control get pods
kubectl -n neoworks-control port-forward svc/neoworks-api 8081:8081   # curl /health

# after a code change: rebuild dist/api, rebuild+load the image, then
kubectl -n neoworks-control rollout restart deploy/neoworks-api
```

## Architecture

| Layer            | What runs it                                    | HA model |
|------------------|-------------------------------------------------|----------|
| API + OAuth      | `neoworks-api` Deployment + Service + HPA        | stateless; N replicas behind one Service, autoscaled on CPU |
| Control-plane DB | TiKV cluster (`TidbCluster`, PD+TiKV) + stateless SurrealDB compute | Raft-replicated storage; compute pods fail over behind the `control-surreal` Service |
| Cache / sessions | `RedisFailover` (1 master + 2 replicas + 3 sentinels) | sentinel-elected master failover; client follows via sentinels |
| Object storage   | MinIO (kind) → external managed S3 (prod)        | n/a in-cluster for prod |
| Tenant DBs       | per-org single-node rocksdb StatefulSet (unchanged) | **HA deferred** |

## Prerequisites (install once, cluster-scoped)

These CRDs + operators must exist before applying the base (the base contains
their custom resources):

```sh
# tidb-operator (manages PD/TiKV)
helm repo add pingcap https://charts.pingcap.org
kubectl create namespace tidb-admin
helm install --namespace tidb-admin tidb-operator pingcap/tidb-operator \
  --set operatorImage=pingcap/tidb-operator:v1.6.0

# spotahome redis-operator
helm repo add redis-operator https://spotahome.github.io/redis-operator
helm install redis-operator redis-operator/redis-operator

# metrics-server (for the HPA) — already installed in the existing kind cluster
```

## Secrets (created imperatively, never committed)

```sh
# Shared OAuth signing key — SEC1 P-256 PEM. MUST be shared by every API pod,
# otherwise tokens from one pod fail verification on another.
openssl ecparam -genkey -name prime256v1 -noout -out /tmp/auth.pem
kubectl -n neoworks-control create secret generic neoworks-signing-key \
  --from-file=auth.pem=/tmp/auth.pem

# Per-org instance root-password encryption key (base64 of exactly 32 bytes).
kubectl -n neoworks-control create secret generic neoworks-api-secrets \
  --from-literal=instance-key="$(openssl rand -base64 32)"
```

The `neoworks-control` namespace is created by the base, so create the namespace
first (`kubectl apply -f base/00-namespaces.yaml`) or create the secrets after the
first `kubectl apply -k base`.

## Version pinning (verification gate)

`base/30-surreal-tikv.yaml` (TiKV `v7.5.1`) and `base/31-surreal-compute.yaml`
(SurrealDB `v2.1.4`) MUST be a pair known to interoperate. A SurrealDB/TiKV
data-format skew corrupts or locks the store (see surrealdb/surrealdb#4697). Verify
the exact pair against SurrealDB's TiKV docs before rollout; never use a `latest`
or `latest-dev` tag for the control-plane compute image.

## Build + apply (kind)

```sh
cd apps/api

# 1. Build static binaries the image expects in dist/
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dist/api ./cmd/api
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dist/migrate ./cmd/migrate
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dist/provisiondemo ./cmd/provisiondemo

# 2. Build + load the image (imagePullPolicy: Never expects a preloaded image)
docker build --provenance=false -f deploy/Dockerfile.demo -t neoworks-api:demo .
kind load docker-image neoworks-api:demo --name neoworks

# 3. Namespaces + secrets (see above), then the whole base
kubectl apply -f deploy/k8s/base/00-namespaces.yaml
#   ...create the two secrets...
kubectl apply -k deploy/k8s/base

# 4. Watch it come up (migrate Job runs before the API is useful)
kubectl -n neoworks-control get pods,svc,hpa
kubectl -n neoworks-control wait --for=condition=complete job/neoworks-migrate --timeout=300s
```

Production: `kubectl apply -k deploy/k8s/overlays/prod` (after the prod
prerequisites: registry image tag, external S3 `neoworks-s3` Secret, ingress
controller + cert-manager, real storageClassName on the TiKV/Redis PVCs).

## Verification

```sh
kubectl -n neoworks-control port-forward svc/neoworks-api 8081:8081
curl -s localhost:8081/health           # -> ok

# Multi-pod OAuth correctness: a token minted on one pod must verify on another.
# SurrealDB failover: delete a tikv pod -> cluster stays writable.
# Redis failover: delete the redis master pod -> sentinels promote a replica.
# HPA: drive CPU load -> replicas rise toward maxReplicas, then fall.
```
