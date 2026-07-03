package provisioner

import "testing"

func TestInstanceName(t *testing.T) {
	cases := map[string]string{
		"abc123":          "neoworks-org-abc123",
		"Org With Spaces": "neoworks-org-org-with-spaces",
		"org:abc-def":     "neoworks-org-org-abc-def",
		"":                "neoworks-org-org",
		"---":             "neoworks-org-org",
	}
	for in, want := range cases {
		if got := instanceName(in); got != want {
			t.Errorf("instanceName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseLeadingInt(t *testing.T) {
	if got := parseLeadingInt("4096\t/data"); got != 4096 {
		t.Errorf("parseLeadingInt = %v, want 4096", got)
	}
	if got := parseLeadingInt(""); got != 0 {
		t.Errorf("parseLeadingInt(empty) = %v, want 0", got)
	}
}

func TestParseKubectlTop(t *testing.T) {
	// "<pod> <cpu> <mem>"; 250m == 25% of one core, 128Mi == 128*2^20 bytes.
	cpu, mem := parseKubectlTop("neoworks-org-x-0   250m   128Mi")
	if cpu != 25 {
		t.Errorf("cpu = %v, want 25", cpu)
	}
	if mem != 128<<20 {
		t.Errorf("mem = %d, want %d", mem, 128<<20)
	}

	// Whole-core CPU + Gi memory.
	cpu, mem = parseKubectlTop("pod 2 3Gi")
	if cpu != 200 {
		t.Errorf("cpu = %v, want 200", cpu)
	}
	if mem != 3<<30 {
		t.Errorf("mem = %d, want %d", mem, 3<<30)
	}

	// Malformed line degrades to zeros.
	if cpu, mem := parseKubectlTop(""); cpu != 0 || mem != 0 {
		t.Errorf("empty = (%v,%d), want zeros", cpu, mem)
	}
}

func TestParseK8sQuantityBytes(t *testing.T) {
	cases := map[string]int64{
		"128Mi":   128 << 20,
		"2Gi":     2 << 30,
		"512Ki":   512 << 10,
		"1048576": 1048576,
		"":        0,
		"garbage": 0,
	}
	for in, want := range cases {
		if got := parseK8sQuantityBytes(in); got != want {
			t.Errorf("parseK8sQuantityBytes(%q) = %d, want %d", in, got, want)
		}
	}
}
