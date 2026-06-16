# Helm Chart Flags to Maximize Image Rendering

This document lists all the Helm chart flags that can be set to enable additional container images in the Trento Server deployment.

## Parent Chart (trento-server)

### Core Subcharts - Enable/Disable

| Flag | Default | Images Added | Notes |
|------|---------|--------------|-------|
| `--set trento-web.enabled=true` | true | trento-web | Trento Web UI |
| `--set trento-wanda.enabled=true` | true | trento-wanda, checks | Trento Wanda API + checks runner |
| `--set trento-mcp-server.enabled=true` | false | mcp-server-trento | Model Context Protocol Server |
| `--set postgresql.enabled=true` | true | suse/postgres | PostgreSQL database |
| `--set prometheus.enabled=true` | true | prometheus-server | Prometheus monitoring |
| `--set rabbitmq.enabled=true` | true | rabbitmq | RabbitMQ message broker |

### Prometheus Subcharts

When `prometheus.enabled=true`:

| Flag | Default | Images Added | Notes |
|------|---------|--------------|-------|
| `--set prometheus.server.enabled=true` | true | prometheus | Prometheus server |
| `--set prometheus.alertmanager.enabled=true` | false | alertmanager | Prometheus Alert Manager |
| `--set prometheus.prometheus-pushgateway.enabled=true` | false | pushgateway | Prometheus Push Gateway |
| `--set prometheus.configmapReload.prometheus.enabled=true` | false | configmap-reload | Config auto-reload sidecar |
| `--set prometheus.kube-state-metrics.enabled=true` | false | kube-state-metrics | Kubernetes state metrics |
| `--set prometheus.prometheus-node-exporter.enabled=true` | false | node-exporter | Node metrics exporter |

### Prometheus Auth Sidecar

When `prometheus.server.enabled=true`:

| Flag | Default | Images Added | Notes |
|------|---------|--------------|-------|
| `--set prometheus.server.sidecarContainers.auth-proxy.image=registry.suse.com/suse/nginx:1.27` | nginx:1.27 | nginx | Auth proxy for Prometheus |

---

## Subchart: PostgreSQL

When `postgresql.enabled=true`:

### Volume Permissions Init Container

| Flag | Default | Images Added | Notes |
|------|---------|--------------|-------|
| `--set postgresql.volumePermissions.enabled=true` | false | bitnami/bitnami-shell:10 | Sets volume ownership |

### PostgreSQL Metrics Exporter

| Flag | Default | Images Added | Notes |
|------|---------|--------------|-------|
| `--set postgresql.metrics.enabled=true` | false | bitnami/postgres-exporter:0.9.0 | PostgreSQL metrics sidecar |
| `--set postgresql.metrics.serviceMonitor.enabled=true` | false | (no image) | Prometheus ServiceMonitor CR |

---

## Subchart: RabbitMQ

When `rabbitmq.enabled=true`:

### Volume Permissions Init Container

| Flag | Default | Images Added | Notes |
|------|---------|--------------|-------|
| `--set rabbitmq.volumePermissions.enabled=true` | true | alpine:3.19 | Sets volume ownership |

### RabbitMQ Metrics

| Flag | Default | Images Added | Notes |
|------|---------|--------------|-------|
| `--set rabbitmq.metrics.enabled=true` | false | (no image) | Enables built-in metrics port |
| `--set rabbitmq.metrics.serviceMonitor.enabled=true` | false | (no image) | Prometheus ServiceMonitor CR |

### RabbitMQ Init Containers (Custom)

You can add custom init containers via:
- `--set rabbitmq.initContainers=<custom-init-container-spec>`

---

## Subchart: Trento Web

When `trento-web.enabled=true`:

### PostgreSQL Init Container

| Flag | Default | Images Added | Notes |
|------|---------|--------------|-------|
| Included automatically | - | suse/postgres:14 | Database migration init container |

---

## Subchart: Trento Wanda

When `trento-wanda.enabled=true`:

### Init Containers

| Flag | Default | Images Added | Notes |
|------|---------|--------------|-------|
| Included automatically | - | ghcr.io/trento-project/checks | Checks migration init container |
| Included automatically | - | suse/postgres:14 | Database migration init container |

---

## Subchart: Trento MCP Server

When `trento-mcp-server.enabled=true`:

No additional images beyond the main service container.

---

## PostgreSQL Replication & Sidecars

When `postgresql.enabled=true` and `replication.enabled=true`:

| Flag | Default | Images Added | Notes |
|------|---------|--------------|-------|
| `--set postgresql.replication.enabled=true` | false | suse/postgres (read replicas) | Enables PostgreSQL read replicas |
| `--set postgresql.primary.sidecars[0].image=<image>` | [] | custom | Custom sidecars for primary |
| `--set postgresql.readReplicas.sidecars[0].image=<image>` | [] | custom | Custom sidecars for read replicas |

---

## RabbitMQ Sidecars & Custom Containers

When `rabbitmq.enabled=true`:

| Flag | Default | Images Added | Notes |
|------|---------|--------------|-------|
| `--set rabbitmq.sidecars[0].image=<image>` | [] | custom | Custom sidecars for RabbitMQ |
| `--set rabbitmq.initContainers[0].image=<image>` | [] | custom | Custom init containers |

---

## Complete "Maximum Images" Helm Command

To enable ALL available images:

```bash
helm install trento ./charts/trento-server \
  --set trento-web.enabled=true \
  --set trento-wanda.enabled=true \
  --set trento-mcp-server.enabled=true \
  --set postgresql.enabled=true \
  --set postgresql.volumePermissions.enabled=true \
  --set postgresql.metrics.enabled=true \
  --set postgresql.metrics.serviceMonitor.enabled=true \
  --set postgresql.replication.enabled=true \
  --set postgresql.primary.sidecars=null \
  --set postgresql.readReplicas.sidecars=null \
  --set postgresql.shmVolume.enabled=true \
  --set postgresql.shmVolume.chmod.enabled=true \
  --set prometheus.enabled=true \
  --set prometheus.server.enabled=true \
  --set prometheus.alertmanager.enabled=true \
  --set prometheus.prometheus-pushgateway.enabled=true \
  --set prometheus.configmapReload.prometheus.enabled=true \
  --set prometheus.kube-state-metrics.enabled=true \
  --set prometheus.prometheus-node-exporter.enabled=true \
  --set prometheus.server.auth.type=basic \
  --set rabbitmq.enabled=true \
  --set rabbitmq.volumePermissions.enabled=true \
  --set rabbitmq.metrics.enabled=true \
  --set rabbitmq.metrics.serviceMonitor.enabled=true \
  --set rabbitmq.sidecars=null \
  --set global.rabbitmq.tls.mtls.enabled=true \
  --set global.rabbitmq.tls.mtls.certManager.enabled=true
```

**Additional steps for full image coverage:**
1. Run `helm test <release>` to deploy busybox test pods
2. Install cert-manager if using mTLS (required for kubectl waiter job)
3. Optionally inject custom init containers/sidecars via values

---

## Complete List of All Discoverable Images

When using the "maximum images" command with ALL flags enabled, the following **18 unique container images** are rendered:

### Trento Project Images (4)
1. `ghcr.io/trento-project/trento-web:3.1.0` - Web UI
2. `ghcr.io/trento-project/trento-wanda:2.1.0` - Wanda API
3. `ghcr.io/trento-project/checks:1.3.0` - Checks runner (Wanda init)
4. `ghcr.io/trento-project/mcp-server-trento:1.1.0` - MCP Server

### SUSE Registry Images (2)
5. `registry.suse.com/suse/postgres:14` - PostgreSQL database
6. `registry.suse.com/suse/nginx:1.27` - Prometheus auth proxy

### Docker Hub Images (4)
7. `docker.io/rabbitmq:3.12.6-management-alpine` - RabbitMQ message broker
8. `docker.io/alpine:3.19` - RabbitMQ volume permissions init
9. `docker.io/bitnami/postgres-exporter:0.9.0-debian-10-r43` - PostgreSQL metrics
10. `docker.io/bitnami/bitnami-shell:10` - PostgreSQL volume permissions init

### Prometheus Community Images (5)
11. `quay.io/prometheus/prometheus:v2.53.1` - Prometheus server
12. `quay.io/prometheus/alertmanager:v0.27.0` - Alert manager
13. `quay.io/prometheus/pushgateway:v1.8.0` - Push gateway
14. `quay.io/prometheus/node-exporter:v1.8.0` - Node metrics exporter
15. `quay.io/prometheus-operator/prometheus-config-reloader:v0.73.2` - Config reloader

### Kubernetes & Infrastructure (3)
16. `registry.k8s.io/kubectl:v1.33.3` - Cert-manager waiter job
17. `registry.k8s.io/kube-state-metrics/kube-state-metrics:v2.12.0` - Kubernetes state metrics
18. `busybox` - Test pods (latest, no specific version)

---

## Quick Reference: Maximum Images Helm Install

Copy and paste this command to deploy with ALL images enabled:

```bash
helm install trento ./charts/trento-server \
  --set trento-web.enabled=true \
  --set trento-wanda.enabled=true \
  --set trento-mcp-server.enabled=true \
  --set postgresql.enabled=true \
  --set postgresql.postgresqlDatabase=trento \
  --set postgresql.volumePermissions.enabled=true \
  --set postgresql.metrics.enabled=true \
  --set postgresql.replication.enabled=true \
  --set postgresql.shmVolume.enabled=true \
  --set postgresql.shmVolume.chmod.enabled=true \
  --set prometheus.enabled=true \
  --set prometheus.server.enabled=true \
  --set prometheus.server.auth.type=none \
  --set prometheus.alertmanager.enabled=true \
  --set prometheus.prometheus-pushgateway.enabled=true \
  --set prometheus.configmapReload.prometheus.enabled=true \
  --set prometheus.kube-state-metrics.enabled=true \
  --set prometheus.prometheus-node-exporter.enabled=true \
  --set rabbitmq.enabled=true \
  --set rabbitmq.volumePermissions.enabled=true \
  --set rabbitmq.metrics.enabled=true \
  --set global.rabbitmq.tls.mtls.enabled=true \
  --set global.rabbitmq.tls.mtls.certManager.enabled=true
```

Then run tests to deploy additional busybox images:
```bash
helm test trento
```

**Result: 18 unique container images deployed**

---

## Image Summary by Source

### Trento Project Images
- `ghcr.io/trento-project/trento-web`
- `ghcr.io/trento-project/trento-wanda`
- `ghcr.io/trento-project/checks`
- `ghcr.io/trento-project/mcp-server-trento`

### SUSE Registry Images
- `registry.suse.com/suse/postgres:14`
- `registry.suse.com/suse/nginx:1.27`

### Docker Hub Images
- `docker.io/rabbitmq:3.12.6-management-alpine`
- `docker.io/bitnami/postgres-exporter:0.9.0-debian-10-r43`
- `docker.io/bitnami/bitnami-shell:10`
- `docker.io/alpine:3.19`

### Prometheus Community Chart Images
- `prom/prometheus:v2.53.1`
- `prom/alertmanager:*` (if enabled)
- `prom/pushgateway:*` (if enabled)
- `jimmidyson/configmap-reload:*` (if enabled)
- `registry.k8s.io/kube-state-metrics:*` (if enabled)
- `prom/node-exporter:*` (if enabled)

### Kubernetes Images
- `registry.k8s.io/kubectl:v1.33.3` (migration hook)

---

## Subchart: Trento Web

When `trento-web.enabled=true`:

### Test Pod (Helm Test)

| Flag | Default | Images Added | Notes |
|------|---------|--------------|-------|
| `helm test` hook | - | busybox | Test pod with wget command |

---

## Subchart: Trento Wanda

When `trento-wanda.enabled=true`:

### Test Pod (Helm Test)

| Flag | Default | Images Added | Notes |
|------|---------|--------------|-------|
| `helm test` hook | - | busybox | Test pod with wget command |

---

## Parent Chart Cert-Manager Resources

When `global.rabbitmq.tls.mtls.enabled=true` AND `global.rabbitmq.tls.mtls.certManager.enabled=true`:

| Flag | Default | Images Added | Notes |
|------|---------|--------------|-------|
| Automatically enabled | - | registry.k8s.io/kubectl:v1.33.3 | Certificate waiter job |

---

## PostgreSQL Advanced Init Container Options

When `postgresql.enabled=true`:

### SHM Volume Chmod Init Container

| Flag | Default | Images Added | Notes |
|------|---------|--------------|-------|
| `--set postgresql.shmVolume.chmod.enabled=true` | true (if shmVolume.enabled=true) | busybox (embedded) | Only if `volumePermissions.enabled=true` |

**Note:** This uses an init container but may reuse busybox if volumePermissions is enabled

### Custom Init Containers (Extensibility)

Both PostgreSQL and RabbitMQ support injecting custom init containers:

- `--set postgresql.primary.extraInitContainers[0].image=<custom-image>`
- `--set rabbitmq.initContainers[0].image=<custom-image>`

---

## Important Notes

1. **ServiceMonitor resources don't add images** - They're CRDs for Prometheus operator, not actual container images
2. **Volume Permissions enabled by default for RabbitMQ** - PostgreSQL has it disabled by default
3. **Auth sidecar requires Prometheus server** - Only rendered if `prometheus.server.enabled=true`
4. **Checks image required for Wanda** - Automatically deployed as init container when wanda is enabled
5. **Database image used in multiple init containers** - PostgreSQL image is shared across web, wanda, and as main service
6. **Test pods use busybox** - Running `helm test` will deploy busybox:latest test pods for web and wanda
7. **Cert-manager job requires cert-manager** - The kubectl:v1.33.3 image is only deployed if cert-manager is installed and configured
8. **SHM volume chmod** - Reuses the volumePermissions image if enabled together
9. **Custom images can be injected** - PostgreSQL and RabbitMQ allow custom init containers via values
