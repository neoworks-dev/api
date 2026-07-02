package config

import "os"

// Every neoworks service URL derives from one base domain so dev and prod differ
// by a single variable (dev: neoworks.localhost, prod: neoworks.dev). Individual
// *_URL env vars still override the derived value where one is read explicitly.

// BaseDomain is the root domain for all services.
func BaseDomain() string {
	if value := os.Getenv("BASE_DOMAIN"); value != "" {
		return value
	}
	return "neoworks.localhost"
}

// BaseScheme is the URL scheme for all services (Caddy terminates TLS in both
// dev and prod, so this is normally https).
func BaseScheme() string {
	if value := os.Getenv("BASE_SCHEME"); value != "" {
		return value
	}
	return "https"
}

// ServiceURL returns the base URL of a service subdomain, e.g.
// ServiceURL("oauth") -> https://oauth.neoworks.localhost. An empty subdomain
// returns the root web-app URL.
func ServiceURL(subdomain string) string {
	if subdomain == "" {
		return BaseScheme() + "://" + BaseDomain()
	}
	return BaseScheme() + "://" + subdomain + "." + BaseDomain()
}
