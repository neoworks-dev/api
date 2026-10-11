package domainproof

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

const (
	lookupTimeout   = 5 * time.Second
	maxProofBytes   = 1024
	maxRedirects    = 3
	proofUserAgent  = "neoworks-domain-verification/1"
	notFoundMessage = "no record"
)

// ErrBlockedAddress means the domain resolves to an address a server must not
// connect to on a stranger's behalf.
var ErrBlockedAddress = errors.New("domain resolves to a non-public address")

var carrierGradeNAT = netip.MustParsePrefix("100.64.0.0/10")

// isPublicAddress reports whether the address is one on the public internet.
func isPublicAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return false
	}
	return !carrierGradeNAT.Contains(address)
}

// refuseNonPublic runs when a connection is about to be made, after DNS, so a
// domain cannot point the check at an internal service.
func refuseNonPublic(_ string, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	parsed, err := netip.ParseAddr(host)
	if err != nil || !isPublicAddress(parsed) {
		return ErrBlockedAddress
	}
	return nil
}

// NetworkProver looks domains up on the real network.
type NetworkProver struct {
	resolver *net.Resolver
	client   *http.Client
}

func NewNetworkProver() *NetworkProver {
	dialer := &net.Dialer{Timeout: lookupTimeout, Control: refuseNonPublic}
	transport := &http.Transport{DialContext: dialer.DialContext, TLSHandshakeTimeout: lookupTimeout, DisableKeepAlives: true}
	return &NetworkProver{
		resolver: net.DefaultResolver,
		client:   &http.Client{Timeout: lookupTimeout, Transport: transport, CheckRedirect: sameHostRedirect},
	}
}

// sameHostRedirect follows a few redirects that stay on the domain being proven.
func sameHostRedirect(next *http.Request, via []*http.Request) error {
	if len(via) > maxRedirects || next.URL.Scheme != "https" || next.URL.Hostname() != via[0].URL.Hostname() {
		return http.ErrUseLastResponse
	}
	return nil
}

func (prover *NetworkProver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	records, err := prover.resolver.LookupTXT(ctx, name)
	var missing *net.DNSError
	if errors.As(err, &missing) && missing.IsNotFound {
		return nil, nil
	}
	return records, err
}

func (prover *NetworkProver) FetchWellKnown(ctx context.Context, domain string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+domain+WellKnownPath, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("User-Agent", proofUserAgent)
	response, err := prover.client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: %s", notFoundMessage, response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxProofBytes))
	return string(body), err
}
