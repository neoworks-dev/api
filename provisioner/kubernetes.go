package provisioner

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// KubernetesConfig configures the kubernetes driver. Zero values fall back to
// sensible defaults in NewKubernetesProvisioner.
type KubernetesConfig struct {
	Image        string // SurrealDB image, e.g. "surrealdb/surrealdb:latest-dev"
	Namespace    string // namespace instances are created in (default "neoworks-tenants")
	Kubectl      string // kubectl binary (default "kubectl")
	StorageSize  string // PVC size per instance (default "1Gi")
	StorageClass string // optional PVC storage class; empty uses the cluster default
}

// KubernetesProvisioner runs each org's SurrealDB as a StatefulSet + Service in a
// kubernetes cluster. Like the docker driver it shells out to the cluster CLI
// (kubectl) rather than linking a client library, keeping the substrate swap
// mechanical. It assumes it runs inside the cluster: instances are addressed by
// their in-cluster Service DNS, so no port publishing is needed.
type KubernetesProvisioner struct {
	image        string
	namespace    string
	kubectl      string
	storageSize  string
	storageClass string
}

func NewKubernetesProvisioner(cfg KubernetesConfig) *KubernetesProvisioner {
	image := cfg.Image
	if image == "" {
		image = "surrealdb/surrealdb:latest-dev"
	}
	namespace := cfg.Namespace
	if namespace == "" {
		namespace = "neoworks-tenants"
	}
	kubectl := cfg.Kubectl
	if kubectl == "" {
		kubectl = "kubectl"
	}
	storageSize := cfg.StorageSize
	if storageSize == "" {
		storageSize = "1Gi"
	}
	return &KubernetesProvisioner{
		image:        image,
		namespace:    namespace,
		kubectl:      kubectl,
		storageSize:  storageSize,
		storageClass: cfg.StorageClass,
	}
}

// Provision creates (or recreates) the org's StatefulSet + Service and waits for
// the pod to become ready and serve /health. It is idempotent: a stale workload
// from a prior failed attempt is deleted and rebuilt with fresh credentials,
// since the control-plane org_instance row is the source of truth.
func (k *KubernetesProvisioner) Provision(ctx context.Context, orgID string) (InstanceHandle, error) {
	name := instanceName(orgID)

	// Remove any orphan workload (keep the PVC so data survives a rebuild).
	_ = k.run(ctx, "delete", "statefulset", name, "--ignore-not-found", "--wait=false")
	_ = k.run(ctx, "delete", "service", name, "--ignore-not-found")

	rootUser, err := randToken(6)
	if err != nil {
		return InstanceHandle{}, fmt.Errorf("generate root user: %w", err)
	}
	rootUser = "root_" + rootUser
	rootPass, err := randSecret()
	if err != nil {
		return InstanceHandle{}, fmt.Errorf("generate root pass: %w", err)
	}

	manifest := k.manifest(name, rootUser, rootPass)
	if err := k.apply(ctx, manifest); err != nil {
		return InstanceHandle{}, fmt.Errorf("kubectl apply: %w", err)
	}

	// Bound the wait on the pod becoming ready, then confirm SurrealDB itself is
	// serving over the Service DNS before handing back the endpoint.
	if err := k.run(ctx, "rollout", "status", "statefulset/"+name, "--timeout=120s"); err != nil {
		_ = k.destroy(ctx, name)
		return InstanceHandle{}, fmt.Errorf("rollout status: %w", err)
	}

	host := fmt.Sprintf("%s.%s.svc.cluster.local", name, k.namespace)
	address := host + ":8000"
	if err := waitForHealthy(ctx, address, 30*time.Second); err != nil {
		_ = k.destroy(ctx, name)
		return InstanceHandle{}, fmt.Errorf("instance not ready: %w", err)
	}

	return InstanceHandle{
		Endpoint: "ws://" + address,
		Handle:   name,
		RootUser: rootUser,
		RootPass: rootPass,
		Host:     host,
	}, nil
}

func (k *KubernetesProvisioner) Destroy(ctx context.Context, handle string) error {
	if handle == "" {
		return nil
	}
	return k.destroy(ctx, handle)
}

// destroy removes the workload, its Service, and the backing PVC. PVC deletion is
// best-effort; the data is gone with the volume anyway.
func (k *KubernetesProvisioner) destroy(ctx context.Context, name string) error {
	if err := k.run(ctx, "delete", "statefulset", name, "--ignore-not-found"); err != nil {
		return fmt.Errorf("delete statefulset: %w", err)
	}
	_ = k.run(ctx, "delete", "service", name, "--ignore-not-found")
	// StatefulSet volumeClaimTemplates leave the PVC behind; remove it by label.
	_ = k.run(ctx, "delete", "pvc", "-l", "app="+name, "--ignore-not-found")
	return nil
}

// Stats samples the pod's CPU + memory (via metrics-server) and data-volume size
// (via exec du). All are best-effort; a value the driver cannot read comes back
// as zero rather than failing the whole sample.
func (k *KubernetesProvisioner) Stats(ctx context.Context, handle string) (ResourceStats, error) {
	if handle == "" {
		return ResourceStats{}, nil
	}
	var stats ResourceStats
	pod := handle + "-0" // stable StatefulSet pod name

	// `kubectl top` needs metrics-server; treat its absence as zero CPU/mem.
	if topOut, err := k.runOut(ctx, "top", "pod", pod, "--no-headers"); err == nil {
		cpu, mem := parseKubectlTop(topOut)
		stats.CPUPercent = cpu
		stats.MemBytes = mem
	}

	if duOut, err := k.runOut(ctx, "exec", pod, "--", "du", "-sb", "/data"); err == nil {
		stats.StorageBytes = parseLeadingInt(duOut)
	}
	return stats, nil
}

// manifest renders the StatefulSet + Service YAML for an instance. Credentials
// are passed as start flags, matching the docker driver; for a hardened setup
// they would move to a Secret mounted as env.
func (k *KubernetesProvisioner) manifest(name, rootUser, rootPass string) string {
	storageClassLine := ""
	if k.storageClass != "" {
		storageClassLine = "\n        storageClassName: " + k.storageClass
	}
	return fmt.Sprintf(`apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: %[1]s
  namespace: %[2]s
  labels:
    app: %[1]s
spec:
  serviceName: %[1]s
  replicas: 1
  selector:
    matchLabels:
      app: %[1]s
  template:
    metadata:
      labels:
        app: %[1]s
    spec:
      containers:
        - name: surrealdb
          image: %[3]s
          args: ["start", "--user", "%[4]s", "--pass", "%[5]s", "--bind", "0.0.0.0:8000", "rocksdb:/data/tenant.db"]
          ports:
            - containerPort: 8000
          volumeMounts:
            - name: data
              mountPath: /data
          readinessProbe:
            httpGet:
              path: /health
              port: 8000
            initialDelaySeconds: 2
            periodSeconds: 2
  volumeClaimTemplates:
    - metadata:
        name: data
        labels:
          app: %[1]s
      spec:
        accessModes: ["ReadWriteOnce"]
        resources:
          requests:
            storage: %[6]s%[7]s
---
apiVersion: v1
kind: Service
metadata:
  name: %[1]s
  namespace: %[2]s
  labels:
    app: %[1]s
spec:
  selector:
    app: %[1]s
  ports:
    - port: 8000
      targetPort: 8000
`, name, k.namespace, k.image, rootUser, rootPass, k.storageSize, storageClassLine)
}

// apply pipes a manifest to `kubectl apply -f -`.
func (k *KubernetesProvisioner) apply(ctx context.Context, manifest string) error {
	cmd := exec.CommandContext(ctx, k.kubectl, "-n", k.namespace, "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (k *KubernetesProvisioner) run(ctx context.Context, args ...string) error {
	_, err := k.runOut(ctx, args...)
	return err
}

func (k *KubernetesProvisioner) runOut(ctx context.Context, args ...string) (string, error) {
	full := append([]string{"-n", k.namespace}, args...)
	cmd := exec.CommandContext(ctx, k.kubectl, full...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// parseKubectlTop reads a `kubectl top pod --no-headers` line ("<pod> <cpu> <mem>")
// into CPU percent (1000m = 100% of one core) and memory bytes.
func parseKubectlTop(line string) (cpuPercent float64, memBytes int64) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return 0, 0
	}
	return parseMillicoresPercent(fields[1]), parseK8sQuantityBytes(fields[2])
}

// parseMillicoresPercent converts a kubectl CPU quantity ("250m" or "1") into a
// percentage of a single core.
func parseMillicoresPercent(s string) float64 {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "m") {
		v, err := strconv.ParseFloat(strings.TrimSuffix(s, "m"), 64)
		if err != nil {
			return 0
		}
		return v / 10 // 1000m == 100%
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return v * 100 // whole cores
}

var k8sQuantityUnits = []struct {
	suffix string
	scale  float64
}{
	{"Ti", 1 << 40},
	{"Gi", 1 << 30},
	{"Mi", 1 << 20},
	{"Ki", 1 << 10},
}

// parseK8sQuantityBytes reads a kubernetes memory quantity ("128Mi", "2Gi", or a
// plain byte count) into bytes.
func parseK8sQuantityBytes(s string) int64 {
	s = strings.TrimSpace(s)
	for _, unit := range k8sQuantityUnits {
		if !strings.HasSuffix(s, unit.suffix) {
			continue
		}
		num := strings.TrimSpace(strings.TrimSuffix(s, unit.suffix))
		v, err := strconv.ParseFloat(num, 64)
		if err != nil {
			return 0
		}
		return int64(v * unit.scale)
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}
