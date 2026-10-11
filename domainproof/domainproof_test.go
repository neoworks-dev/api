package domainproof

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/neoworks/auth/storage/database"
)

type fakeProver struct {
	records map[string][]string
	files   map[string]string
}

func (fake fakeProver) LookupTXT(_ context.Context, name string) ([]string, error) {
	records, found := fake.records[name]
	if !found {
		return nil, errors.New("no such host")
	}
	return records, nil
}

func (fake fakeProver) FetchWellKnown(_ context.Context, domain string) (string, error) {
	body, found := fake.files[domain]
	if !found {
		return "", errors.New("404")
	}
	return body, nil
}

func TestNormalizeDomainAcceptsPlainHostnamesOnly(t *testing.T) {
	good := map[string]string{"Example.COM": "example.com", " docs.acme.example. ": "docs.acme.example", "a-b.co": "a-b.co"}
	for input, want := range good {
		if got, ok := NormalizeDomain(input); !ok || got != want {
			t.Errorf("%q: got %q %v want %q", input, got, ok, want)
		}
	}
	for _, bad := range []string{"", "localhost", "https://example.com", "example.com/path", "example.com:8443", "127.0.0.1", "-a.com", "a..com", "exa mple.com", "*.example.com", strings.Repeat("a", 64) + ".com"} {
		if got, ok := NormalizeDomain(bad); ok {
			t.Errorf("%q accepted as %q", bad, got)
		}
	}
}

func TestCheckComparesTheTokenOfTheMethod(t *testing.T) {
	prover := fakeProver{
		records: map[string][]string{"acme.example": {"v=spf1 -all", " neoworks-verify=abc "}},
		files:   map[string]string{"docs.acme.example": "neoworks-verify=def\n"},
	}
	cases := []struct {
		method string
		domain string
		token  string
		want   bool
	}{
		{database.DomainMethodDNS, "acme.example", "neoworks-verify=abc", true},
		{database.DomainMethodDNS, "acme.example", "neoworks-verify=other", false},
		{database.DomainMethodWellKnown, "docs.acme.example", "neoworks-verify=def", true},
		{database.DomainMethodWellKnown, "docs.acme.example", "neoworks-verify=abc", false},
		{database.DomainMethodDNS, "docs.acme.example", "neoworks-verify=def", false},
	}
	for _, testCase := range cases {
		passed, err := Check(context.Background(), prover, testCase.method, testCase.domain, testCase.token)
		if testCase.want && err != nil || passed != testCase.want {
			t.Errorf("%+v: passed %v err %v", testCase, passed, err)
		}
	}
	if _, err := Check(context.Background(), prover, "carrier-pigeon", "acme.example", "t"); err == nil {
		t.Error("an unknown method must fail")
	}
}

func TestNewTokenIsPrefixedAndUnique(t *testing.T) {
	first, _ := NewToken()
	second, _ := NewToken()
	if !strings.HasPrefix(first, TokenPrefix) || first == second || len(first) != len(TokenPrefix)+32 {
		t.Fatalf("tokens %q %q", first, second)
	}
}

func TestOnlyPublicAddressesAreConnectedTo(t *testing.T) {
	for address, public := range map[string]string{
		"93.184.216.34:443": "", "10.0.0.1:443": "no", "127.0.0.1:443": "no", "169.254.169.254:80": "no",
		"192.168.1.1:443": "no", "100.64.0.1:443": "no", "[::1]:443": "no", "[fc00::1]:443": "no", "0.0.0.0:80": "no",
		"[::ffff:127.0.0.1]:443": "no", "[2606:4700::1111]:443": "",
	} {
		err := refuseNonPublic("tcp", address, nil)
		if (err == nil) != (public == "") {
			t.Errorf("%s: err %v", address, err)
		}
	}
}

func TestNetworkProverRefusesLoopbackServers(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("token")) }))
	defer server.Close()
	prover := NewNetworkProver()
	host := strings.TrimPrefix(server.URL, "https://")
	if _, err := prover.FetchWellKnown(context.Background(), host); err == nil {
		t.Fatal("a loopback server must not be fetched")
	}
}
