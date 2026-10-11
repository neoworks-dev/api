package database

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// hostOnDomain reports whether host is the domain or one of its subdomains.
func hostOnDomain(host string, domain string) bool {
	host = strings.ToLower(host)
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func hostOnAnyDomain(host string, domains []string) bool {
	for _, domain := range domains {
		if hostOnDomain(host, domain) {
			return true
		}
	}
	return false
}

// httpsHosts lists the hosts of the https URLs; other schemes (loopback,
// custom app schemes) name no domain and need no proof.
func httpsHosts(uris []string) []string {
	hosts := []string{}
	for _, uri := range uris {
		parsed, err := url.Parse(uri)
		if err == nil && parsed.Scheme == "https" && parsed.Hostname() != "" {
			hosts = append(hosts, parsed.Hostname())
		}
	}
	return hosts
}

// AppIsVerified reports whether an app counts as verified: it has an https
// redirect URI, and every https redirect URI and the homepage are on a verified
// domain of its owner.
func AppIsVerified(domains []string, redirectURIs []string, homepage string) bool {
	hosts := httpsHosts(redirectURIs)
	if len(hosts) == 0 {
		return false
	}
	if homepage != "" {
		hosts = append(hosts, httpsHosts([]string{homepage})...)
	}
	for _, host := range hosts {
		if !hostOnAnyDomain(host, domains) {
			return false
		}
	}
	return true
}

// refreshVerification stores whether the app is verified against the owner's
// verified domains and reports whether that changed.
func (s *SurrealStore) refreshVerification(ctx context.Context, app *App) (bool, error) {
	if app.FirstParty {
		return false, nil
	}
	domains, err := s.VerifiedDomainNames(ctx, app.Owner.Handle)
	if err != nil {
		return false, err
	}
	verified := AppIsVerified(domains, app.RedirectURIs, app.Homepage)
	if verified == app.Verified {
		return false, nil
	}
	err = queryExec(ctx, s.DB, "UPDATE $client SET verified = $verified",
		map[string]any{"client": clientRecord(app.ID), "verified": verified})
	if err != nil {
		return false, fmt.Errorf("store app verification: %w", err)
	}
	return true, nil
}

// refreshedApp returns the app after bringing its stored verification up to date.
func (s *SurrealStore) refreshedApp(ctx context.Context, clientID string) (*App, error) {
	app, err := s.GetApp(ctx, clientID)
	if err != nil {
		return nil, err
	}
	changed, err := s.refreshVerification(ctx, app)
	if err != nil || !changed {
		return app, err
	}
	return s.GetApp(ctx, clientID)
}

type dbClientID struct {
	ID string `json:"id"`
}

// RefreshOwnerVerification re-evaluates the verification of every app of the
// owner, after its domains changed. It returns the apps whose state changed.
func (s *SurrealStore) RefreshOwnerVerification(ctx context.Context, handle string) ([]string, error) {
	owner, err := s.ownerRecord(ctx, handle)
	if err != nil {
		return nil, err
	}
	rows, err := queryRows[dbClientID](ctx, s.DB, "SELECT record::id(id) AS id FROM client WHERE owner = $owner",
		map[string]any{"owner": owner})
	if err != nil {
		return nil, fmt.Errorf("list owner apps: %w", err)
	}
	changedApps := []string{}
	for _, row := range rows {
		changed, err := s.refreshAppByID(ctx, row.ID)
		if err != nil {
			return nil, err
		}
		if changed {
			changedApps = append(changedApps, row.ID)
		}
	}
	return changedApps, nil
}

func (s *SurrealStore) refreshAppByID(ctx context.Context, clientID string) (bool, error) {
	app, err := s.GetApp(ctx, clientID)
	if err != nil {
		return false, err
	}
	return s.refreshVerification(ctx, app)
}
