package apps

import (
	"context"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/neoworks/auth/storage/database"
)

const (
	maxNameRunes        = 60
	maxDescriptionRunes = 280
	maxHomepageRunes    = 200
	maxRedirectURIs     = 10
	maxRedirectURIRunes = 300
	maxScopes           = 40
	maxReasonRunes      = 280
	maxPort             = 65535
)

var (
	identityScopes = []string{"openid", "profile", "email"}

	// A collection segment follows the registry rule apps/oauth applies.
	collectionSegmentPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	collectionActions        = []string{"read", "write", "share"}

	// The OAuth server matches loopback IP redirects on any port, so their port is optional;
	// localhost is matched exactly and needs one.
	loopbackPattern     = regexp.MustCompile(`^http://(127\.0\.0\.1|\[::1\])(:([0-9]{1,5}))?(/\S*)?$`)
	localhostPattern    = regexp.MustCompile(`^http://localhost:([0-9]{1,5})(/\S*)?$`)
	customSchemePattern = regexp.MustCompile(`^[a-z][a-z0-9-]*(\.[a-z0-9-]+)+://\S*$`)
)

// fieldError is a rejected request field, answered as 400 with the field named.
type fieldError struct {
	code    string
	field   string
	message string
}

func (err *fieldError) Error() string { return err.field + ": " + err.message }

func invalidField(field string, message string) error {
	return &fieldError{code: "invalid_request", field: field, message: message}
}

// appRequest holds the fields of a create or patch body; a nil field is absent.
type appRequest struct {
	Type         *string                    `json:"type"`
	Name         *string                    `json:"name"`
	Description  *string                    `json:"description"`
	Homepage     *string                    `json:"homepage"`
	RedirectURIs *[]string                  `json:"redirectUris"`
	Scopes       *[]database.RequestedScope `json:"scopes"`
}

func parseText(field string, value string, minRunes int, maxRunes int) (string, error) {
	text := strings.TrimSpace(value)
	length := utf8.RuneCountInString(text)
	if !utf8.ValidString(text) || length < minRunes || length > maxRunes {
		return "", invalidField(field, field+" must be between "+strconv.Itoa(minRunes)+" and "+strconv.Itoa(maxRunes)+" characters")
	}
	return text, nil
}

func parseHomepage(value string) (string, error) {
	homepage, err := parseText("homepage", value, 0, maxHomepageRunes)
	if err != nil {
		return "", err
	}
	if homepage != "" && !isHTTPSURL(homepage) {
		return "", invalidField("homepage", "homepage must be an https:// URL")
	}
	return homepage, nil
}

func isHTTPSURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Hostname() != ""
}

// isValidRedirectURI accepts https URLs, loopback IP URLs with or without a
// port, localhost URLs with a port and reverse-domain custom schemes.
func isValidRedirectURI(uri string) bool {
	if isHTTPSURL(uri) {
		return true
	}
	if customSchemePattern.MatchString(uri) {
		return true
	}
	localhostMatch := localhostPattern.FindStringSubmatch(uri)
	if localhostMatch != nil {
		return isValidPort(localhostMatch[1])
	}
	match := loopbackPattern.FindStringSubmatch(uri)
	if match == nil {
		return false
	}
	if match[3] == "" {
		return true
	}
	return isValidPort(match[3])
}

func isValidPort(digits string) bool {
	port, _ := strconv.Atoi(digits)
	return port >= 1 && port <= maxPort
}

func parseRedirectURIs(values []string) ([]string, error) {
	if len(values) == 0 || len(values) > maxRedirectURIs {
		return nil, invalidField("redirectUris", "provide between 1 and "+strconv.Itoa(maxRedirectURIs)+" redirect URIs")
	}
	uris := make([]string, 0, len(values))
	for _, value := range values {
		uri, err := parseText("redirectUris", value, 1, maxRedirectURIRunes)
		if err != nil {
			return nil, err
		}
		if !isValidRedirectURI(uri) {
			return nil, invalidField("redirectUris", uri+" is not allowed: use https://, http://localhost:<port>, http://127.0.0.1 with any port or a reverse-domain scheme such as com.example.app://")
		}
		if slices.Contains(uris, uri) {
			return nil, invalidField("redirectUris", "redirect URIs must be unique")
		}
		uris = append(uris, uri)
	}
	return uris, nil
}

// collectionOf splits `@scope/name:action` into the collection and its action.
func collectionOf(scope string) (collection string, action string, ok bool) {
	separator := strings.LastIndex(scope, ":")
	if separator < 0 {
		return "", "", false
	}
	collection, action = scope[:separator], scope[separator+1:]
	path, hasAt := strings.CutPrefix(collection, "@")
	if !hasAt || !slices.Contains(collectionActions, action) {
		return "", "", false
	}
	scopeName, name, hasSlash := strings.Cut(path, "/")
	if !hasSlash || !collectionSegmentPattern.MatchString(scopeName) || !collectionSegmentPattern.MatchString(name) {
		return "", "", false
	}
	return collection, action, true
}

func isWellFormedScope(scope string) bool {
	if slices.Contains(identityScopes, scope) {
		return true
	}
	_, _, ok := collectionOf(scope)
	return ok
}

func parseScope(requested database.RequestedScope) (database.RequestedScope, error) {
	if !isWellFormedScope(requested.Scope) {
		return database.RequestedScope{}, invalidField("scopes", requested.Scope+" is not openid, profile, email or @scope/name:read|write|share")
	}
	reason, err := parseText("scopes", requested.Reason, 1, maxReasonRunes)
	if err != nil {
		return database.RequestedScope{}, err
	}
	return database.RequestedScope{Scope: requested.Scope, Reason: reason}, nil
}

func parseScopes(requested []database.RequestedScope) ([]database.RequestedScope, error) {
	if len(requested) > maxScopes {
		return nil, invalidField("scopes", "request at most "+strconv.Itoa(maxScopes)+" scopes")
	}
	scopes := make([]database.RequestedScope, 0, len(requested))
	seen := map[string]bool{}
	for _, entry := range requested {
		scope, err := parseScope(entry)
		if err != nil {
			return nil, err
		}
		if seen[scope.Scope] {
			return nil, invalidField("scopes", "each scope can only be requested once")
		}
		seen[scope.Scope] = true
		scopes = append(scopes, scope)
	}
	return scopes, nil
}

func collectionsOf(scopes []database.RequestedScope) []string {
	collections := []string{}
	for _, scope := range scopes {
		collection, _, ok := collectionOf(scope.Scope)
		if ok && !slices.Contains(collections, collection) {
			collections = append(collections, collection)
		}
	}
	return collections
}

// checkCollectionsPublished refuses scopes of collections whose schema is not
// published, the same check consent makes before it creates a root.
func checkCollectionsPublished(ctx context.Context, store *database.SurrealStore, scopes []database.RequestedScope) error {
	collections := collectionsOf(scopes)
	if len(collections) == 0 {
		return nil
	}
	published, err := store.PublishedCollections(ctx, collections)
	if err != nil {
		return err
	}
	for _, collection := range collections {
		if !published[collection] {
			return &fieldError{code: "unknown_collection", field: "scopes", message: collection + " is not published in the registry"}
		}
	}
	return nil
}

// parsePatch validates the fields present in the request.
func parsePatch(request appRequest) (database.AppPatch, error) {
	var patch database.AppPatch
	var err error
	if request.Name != nil {
		if patch.Name, err = parsedText(parseText("name", *request.Name, 1, maxNameRunes)); err != nil {
			return patch, err
		}
	}
	if request.Description != nil {
		if patch.Description, err = parsedText(parseText("description", *request.Description, 0, maxDescriptionRunes)); err != nil {
			return patch, err
		}
	}
	if request.Homepage != nil {
		if patch.Homepage, err = parsedText(parseHomepage(*request.Homepage)); err != nil {
			return patch, err
		}
	}
	return parsePatchLists(request, patch)
}

func parsePatchLists(request appRequest, patch database.AppPatch) (database.AppPatch, error) {
	var err error
	if request.RedirectURIs != nil {
		if patch.RedirectURIs, err = parseRedirectURIs(*request.RedirectURIs); err != nil {
			return patch, err
		}
	}
	if request.Scopes != nil {
		scopes, err := parseScopes(*request.Scopes)
		if err != nil {
			return patch, err
		}
		patch.Scopes = &scopes
	}
	return patch, nil
}

func parsedText(text string, err error) (*string, error) {
	if err != nil {
		return nil, err
	}
	return &text, nil
}

func parseType(request appRequest) (string, error) {
	if request.Type == nil || (*request.Type != database.AppTypePublic && *request.Type != database.AppTypeConfidential) {
		return "", invalidField("type", "type must be public or confidential")
	}
	return *request.Type, nil
}

// newAppFields turns a validated patch into the fields of a new app: name and
// redirect URIs are required, the rest default to empty.
func newAppFields(patch database.AppPatch) (database.AppFields, error) {
	if patch.Name == nil {
		return database.AppFields{}, invalidField("name", "name is required")
	}
	if patch.RedirectURIs == nil {
		return database.AppFields{}, invalidField("redirectUris", "redirectUris is required")
	}
	fields := database.AppFields{Name: *patch.Name, RedirectURIs: patch.RedirectURIs, Scopes: []database.RequestedScope{}}
	if patch.Description != nil {
		fields.Description = *patch.Description
	}
	if patch.Homepage != nil {
		fields.Homepage = *patch.Homepage
	}
	if patch.Scopes != nil {
		fields.Scopes = *patch.Scopes
	}
	return fields, nil
}
