package provisioner

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var nonHandleChars = regexp.MustCompile(`[^a-z0-9-]+`)

// instanceName derives a stable, DNS-1123-safe workload name from an org id. It
// is substrate-agnostic: docker container names and kubernetes object names share
// the same constraints.
func instanceName(orgID string) string {
	slug := nonHandleChars.ReplaceAllString(strings.ToLower(orgID), "-")
	slug = strings.Trim(slug, "-")
	if slug == "" {
		slug = "org"
	}
	return "neoworks-org-" + slug
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

// waitForHealthy blocks until SurrealDB's HTTP /health endpoint returns 200 on
// the address, or the timeout elapses. A bare TCP dial is insufficient: a proxy
// in front of the instance (docker's port-publishing proxy, a kube Service) may
// accept the connection before SurrealDB is actually serving and then reset the
// upstream, which surfaces later as a "connection reset by peer" on the admin WS
// connect. Probing /health (served on the same port as ws) confirms the database
// itself is up before we hand back the handle.
func waitForHealthy(ctx context.Context, address string, timeout time.Duration) error {
	healthURL := "http://" + address + "/health"
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 2 * time.Second}
	var lastErr error
	for {
		lastErr = probeHealth(ctx, client, healthURL)
		if lastErr == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return lastErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// probeHealth performs a single GET against the health URL, returning nil only
// on a 200 response.
func probeHealth(ctx context.Context, client *http.Client, healthURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health returned status %d", resp.StatusCode)
	}
	return nil
}

// parseLeadingInt reads the first whitespace-separated integer field (e.g. the
// byte count from `du -sb /data`).
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
