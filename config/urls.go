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

// BasePort is the explicit port of every service origin; empty means the
// scheme's default port.
func BasePort() string {
	return os.Getenv("BASE_PORT")
}

// ServiceURL returns the base URL of a service subdomain, e.g.
// ServiceURL("oauth") -> https://oauth.neoworks.localhost:8443 when BASE_PORT
// is 8443. The port is omitted when it is the scheme's default. An empty
// subdomain returns the root web-app URL.
func ServiceURL(subdomain string) string {
	host := BaseDomain()
	if subdomain != "" {
		host = subdomain + "." + host
	}
	return BaseScheme() + "://" + host + portSuffix(BaseScheme(), BasePort())
}

// portSuffix returns ":port", or "" when the port is empty or the scheme's default.
func portSuffix(scheme, port string) string {
	if port == "" {
		return ""
	}
	if scheme == "https" && port == "443" {
		return ""
	}
	if scheme == "http" && port == "80" {
		return ""
	}
	return ":" + port
}
