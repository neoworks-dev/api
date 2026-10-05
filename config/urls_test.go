package config

import "testing"

func TestServiceURLPort(t *testing.T) {
	cases := []struct {
		name      string
		scheme    string
		port      string
		subdomain string
		want      string
	}{
		{"empty port omitted", "https", "", "oauth", "https://oauth.neoworks.localhost"},
		{"https default omitted", "https", "443", "oauth", "https://oauth.neoworks.localhost"},
		{"http default omitted", "http", "80", "oauth", "http://oauth.neoworks.localhost"},
		{"custom port appended", "https", "8443", "vault", "https://vault.neoworks.localhost:8443"},
		{"root with port", "https", "8443", "", "https://neoworks.localhost:8443"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Setenv("BASE_DOMAIN", "neoworks.localhost")
			t.Setenv("BASE_SCHEME", testCase.scheme)
			t.Setenv("BASE_PORT", testCase.port)
			if got := ServiceURL(testCase.subdomain); got != testCase.want {
				t.Fatalf("ServiceURL(%q) = %q, want %q", testCase.subdomain, got, testCase.want)
			}
		})
	}
}
