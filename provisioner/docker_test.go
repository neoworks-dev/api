package provisioner

import (
	"context"
	"os"
	"testing"
)

func TestContainerName(t *testing.T) {
	cases := map[string]string{
		"abc123":          "neoworks-org-abc123",
		"Org With Spaces": "neoworks-org-org-with-spaces",
		"org:abc-def":     "neoworks-org-org-abc-def",
		"":                "neoworks-org-org",
		"---":             "neoworks-org-org",
	}
	for in, want := range cases {
		if got := containerName(in); got != want {
			t.Errorf("containerName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseHelpers(t *testing.T) {
	if got := parsePercent("12.5%"); got != 12.5 {
		t.Errorf("parsePercent = %v, want 12.5", got)
	}
	if got := parsePercent("not-a-number"); got != 0 {
		t.Errorf("parsePercent(bad) = %v, want 0", got)
	}
	if got := parseLeadingInt("4096\t/data"); got != 4096 {
		t.Errorf("parseLeadingInt = %v, want 4096", got)
	}
	if got := parseLeadingInt(""); got != 0 {
		t.Errorf("parseLeadingInt(empty) = %v, want 0", got)
	}
}

// TestDockerProvisionLifecycle exercises the real docker driver. It is opt-in
// (needs a docker daemon and pulls the SurrealDB image) — set PROVISIONER_DOCKER_TEST=1.
func TestDockerProvisionLifecycle(t *testing.T) {
	if os.Getenv("PROVISIONER_DOCKER_TEST") == "" {
		t.Skip("set PROVISIONER_DOCKER_TEST=1 to run the docker integration test")
	}
	p := NewDockerProvisioner(DockerConfig{})
	ctx := context.Background()

	handle, err := p.Provision(ctx, "test-org-lifecycle")
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	t.Cleanup(func() { _ = p.Destroy(ctx, handle.Handle) })

	if handle.Endpoint == "" || handle.RootUser == "" || handle.RootPass == "" {
		t.Fatalf("incomplete handle: %+v", handle)
	}
	// Idempotent: provisioning the same org again returns a working handle.
	if _, err := p.Provision(ctx, "test-org-lifecycle"); err != nil {
		t.Fatalf("re-provision: %v", err)
	}
	if _, err := p.Stats(ctx, handle.Handle); err != nil {
		t.Fatalf("stats: %v", err)
	}
}
