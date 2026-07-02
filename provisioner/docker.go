package provisioner

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DockerConfig configures the docker driver. Zero values fall back to sensible
// defaults in NewDockerProvisioner.
type DockerConfig struct {
	Image    string // SurrealDB image, e.g. "surrealdb/surrealdb:latest-dev"
	Network  string // optional docker network to attach instances to
	BindHost string // host interface to publish the instance port on (default 127.0.0.1)
	DialHost string // host the API uses to reach the instance (default 127.0.0.1)
}

// DockerProvisioner runs each org's SurrealDB instance as a container on the
// docker host. It shells out to the docker CLI so the API keeps a light
// dependency tree; the interface lets a kubernetes driver replace it later.
type DockerProvisioner struct {
	image    string
	network  string
	bindHost string
	dialHost string
}

func NewDockerProvisioner(cfg DockerConfig) *DockerProvisioner {
	image := cfg.Image
	if image == "" {
		image = "surrealdb/surrealdb:latest-dev"
	}
	bindHost := cfg.BindHost
	if bindHost == "" {
		bindHost = "127.0.0.1"
	}
	dialHost := cfg.DialHost
	if dialHost == "" {
		dialHost = "127.0.0.1"
	}
	return &DockerProvisioner{image: image, network: cfg.Network, bindHost: bindHost, dialHost: dialHost}
}

var nonHandleChars = regexp.MustCompile(`[^a-z0-9-]+`)

// containerName derives a stable, docker-safe container name from an org id.
func containerName(orgID string) string {
	slug := nonHandleChars.ReplaceAllString(strings.ToLower(orgID), "-")
	slug = strings.Trim(slug, "-")
	if slug == "" {
		slug = "org"
	}
	return "neoworks-org-" + slug
}

// Provision creates (or recreates) the org's container and waits until its port
// accepts connections. It is idempotent: a stale container from a prior failed
// attempt is removed and rebuilt with fresh credentials, since the control-plane
// org_instance row is the source of truth.
func (d *DockerProvisioner) Provision(ctx context.Context, orgID string) (InstanceHandle, error) {
	name := containerName(orgID)
	volume := name + "-data"

	// Remove any orphan so the run below starts clean.
	_ = d.run(ctx, "rm", "-f", name)

	rootUser, err := randToken(6)
	if err != nil {
		return InstanceHandle{}, fmt.Errorf("generate root user: %w", err)
	}
	rootUser = "root_" + rootUser
	rootPass, err := randSecret()
	if err != nil {
		return InstanceHandle{}, fmt.Errorf("generate root pass: %w", err)
	}

	args := []string{
		"run", "-d",
		"--name", name,
		"--label", "neoworks.org=" + orgID,
		"--restart", "unless-stopped",
		"-p", d.bindHost + "::8000",
		"-v", volume + ":/data",
	}
	if d.network != "" {
		args = append(args, "--network", d.network)
	}
	args = append(args, d.image,
		"start",
		"--user", rootUser,
		"--pass", rootPass,
		"--bind", "0.0.0.0:8000",
		"rocksdb:/data/tenant.db",
	)
	if _, err := d.runOut(ctx, args...); err != nil {
		return InstanceHandle{}, fmt.Errorf("docker run: %w", err)
	}

	port, err := d.mappedPort(ctx, name)
	if err != nil {
		_ = d.run(ctx, "rm", "-f", name)
		return InstanceHandle{}, fmt.Errorf("resolve port: %w", err)
	}

	address := net.JoinHostPort(d.dialHost, port)
	if err := waitForPort(ctx, address, 20*time.Second); err != nil {
		_ = d.run(ctx, "rm", "-f", name)
		return InstanceHandle{}, fmt.Errorf("instance not ready: %w", err)
	}

	return InstanceHandle{
		Endpoint: "ws://" + address,
		Handle:   name,
		RootUser: rootUser,
		RootPass: rootPass,
		Host:     d.dialHost,
	}, nil
}

func (d *DockerProvisioner) Destroy(ctx context.Context, handle string) error {
	if handle == "" {
		return nil
	}
	if err := d.run(ctx, "rm", "-f", handle); err != nil {
		return fmt.Errorf("remove container: %w", err)
	}
	// Volume removal is best-effort; the data is gone with the container anyway.
	_ = d.run(ctx, "volume", "rm", handle+"-data")
	return nil
}

// Stats samples the container's CPU load and data-volume size. Both are
// best-effort; a driver that cannot read a value returns it as zero rather than
// failing the whole sample.
func (d *DockerProvisioner) Stats(ctx context.Context, handle string) (ResourceStats, error) {
	if handle == "" {
		return ResourceStats{}, nil
	}
	var stats ResourceStats

	cpuOut, err := d.runOut(ctx, "stats", "--no-stream", "--format", "{{.CPUPerc}}", handle)
	if err != nil {
		return stats, fmt.Errorf("docker stats: %w", err)
	}
	stats.CPUPercent = parsePercent(cpuOut)

	// `du` runs inside the container; ignore failures (e.g. distroless image).
	if duOut, err := d.runOut(ctx, "exec", handle, "du", "-sb", "/data"); err == nil {
		stats.StorageBytes = parseLeadingInt(duOut)
	}
	return stats, nil
}

// mappedPort reads the host port docker assigned to the container's 8000/tcp.
func (d *DockerProvisioner) mappedPort(ctx context.Context, name string) (string, error) {
	out, err := d.runOut(ctx, "inspect", "-f",
		`{{ (index (index .NetworkSettings.Ports "8000/tcp") 0).HostPort }}`, name)
	if err != nil {
		return "", err
	}
	port := strings.TrimSpace(out)
	if port == "" {
		return "", fmt.Errorf("no published port for 8000/tcp")
	}
	return port, nil
}

func (d *DockerProvisioner) run(ctx context.Context, args ...string) error {
	_, err := d.runOut(ctx, args...)
	return err
}

func (d *DockerProvisioner) runOut(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// waitForPort blocks until the address accepts a TCP connection or the timeout
// elapses. SurrealDB serves ws on the same port, so an accepted connection means
// the instance is up enough for the caller's SignIn (which retries anyway).
func waitForPort(ctx context.Context, address string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		conn, err := net.DialTimeout("tcp", address, 2*time.Second)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func randToken(nBytes int) (string, error) {
	raw := make([]byte, nBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func randSecret() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func parsePercent(s string) float64 {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "%"))
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return v
}

func parseLeadingInt(s string) int64 {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0
	}
	v, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return 0
	}
	return v
}
