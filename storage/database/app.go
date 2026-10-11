package database

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/neoworks/auth/ownership"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

const (
	AppTypePublic       = "public"
	AppTypeConfidential = "confidential"

	// ReviewStatusNone is the review state of every app until app review (#35) exists.
	ReviewStatusNone = "none"
)

// RequestedScope is a scope an app asks for with the reason it gives users.
type RequestedScope struct {
	Scope  string `json:"scope"`
	Reason string `json:"reason"`
}

// AppSummary is an app as listed.
type AppSummary struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Type         string    `json:"type"`
	ReviewStatus string    `json:"reviewStatus"`
	Verified     bool      `json:"verified"`
	CreatedAt    time.Time `json:"createdAt"`
}

// AppReview is where the app stands in review.
type AppReview struct {
	Status    string     `json:"status"`
	Reason    *string    `json:"reason"`
	UpdatedAt *time.Time `json:"updatedAt"`
}

// App is an OAuth client registered by a person or an organization.
type App struct {
	AppSummary
	Owner        Owner            `json:"owner"`
	Description  string           `json:"description"`
	Homepage     string           `json:"homepage"`
	RedirectURIs []string         `json:"redirectUris"`
	Scopes       []RequestedScope `json:"scopes"`
	LogoURL      *string          `json:"logoUrl"`
	Review       AppReview        `json:"review"`
	UpdatedAt    time.Time        `json:"updatedAt"`
}

// AppFields are the fields a developer edits.
type AppFields struct {
	Name         string
	Description  string
	Homepage     string
	RedirectURIs []string
	Scopes       []RequestedScope
}

// AppPatch changes the fields that are set; the type of an app never changes.
type AppPatch struct {
	Name         *string
	Description  *string
	Homepage     *string
	RedirectURIs []string
	Scopes       *[]RequestedScope
}

// NewApp is an app to register for the owner of OwnerHandle. Type is one of the
// AppType constants; SecretHash is set for confidential apps only. CreatorGrants are added to the creator's
// membership in the same transaction when the owner is an organization.
type NewApp struct {
	ID            string
	OwnerHandle   string
	CreatorID     string
	CreatorGrants []ownership.Grant
	Type          string
	Fields        AppFields
	SecretHash    string
}

type dbScopeReason struct {
	Scope  string `json:"scope"`
	Reason string `json:"reason"`
}

type dbApp struct {
	ID           models.RecordID  `json:"id"`
	Owner        *models.RecordID `json:"owner"`
	Name         *string          `json:"name"`
	Description  string           `json:"description"`
	Homepage     string           `json:"homepage"`
	RedirectURIs []string         `json:"redirect_uris"`
	Scopes       []string         `json:"scopes"`
	ScopeReasons []dbScopeReason  `json:"scope_reasons"`
	Public       bool             `json:"public"`
	CreatedAt    time.Time        `json:"created_at"`
	UpdatedAt    time.Time        `json:"updated_at"`
}

func clientRecord(clientID string) models.RecordID {
	return models.NewRecordID("client", clientID)
}

func (row dbApp) appType() string {
	if row.Public {
		return AppTypePublic
	}
	return AppTypeConfidential
}

func (row dbApp) displayName() string {
	if row.Name == nil {
		return ""
	}
	return *row.Name
}

func (row dbApp) summary() AppSummary {
	return AppSummary{
		ID: recordTail(row.ID), Name: row.displayName(), Type: row.appType(),
		ReviewStatus: ReviewStatusNone, Verified: false, CreatedAt: row.CreatedAt,
	}
}

// requestedScopes pairs every scope of the client with the reason given for it;
// seed clients carry none.
func (row dbApp) requestedScopes() []RequestedScope {
	reasons := make(map[string]string, len(row.ScopeReasons))
	for _, entry := range row.ScopeReasons {
		reasons[entry.Scope] = entry.Reason
	}
	scopes := make([]RequestedScope, 0, len(row.Scopes))
	for _, scope := range row.Scopes {
		scopes = append(scopes, RequestedScope{Scope: scope, Reason: reasons[scope]})
	}
	return scopes
}

func (row dbApp) toApp(owner Owner) *App {
	redirectURIs := row.RedirectURIs
	if redirectURIs == nil {
		redirectURIs = []string{}
	}
	return &App{
		AppSummary: row.summary(), Owner: owner, Description: row.Description, Homepage: row.Homepage,
		RedirectURIs: redirectURIs, Scopes: row.requestedScopes(),
		Review:    AppReview{Status: ReviewStatusNone},
		UpdatedAt: row.UpdatedAt,
	}
}

// ScopeNames lists the scope strings of the requested scopes.
func ScopeNames(scopes []RequestedScope) []string {
	names := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		names = append(names, scope.Scope)
	}
	return names
}

func scopeReasonRows(scopes []RequestedScope) []map[string]any {
	rows := make([]map[string]any, 0, len(scopes))
	for _, scope := range scopes {
		rows = append(rows, map[string]any{"scope": scope.Scope, "reason": scope.Reason})
	}
	return rows
}

// ownerRecord is the record that owns clients for a handle: the organization,
// or the user holding a personal handle.
func (s *SurrealStore) ownerRecord(ctx context.Context, handle string) (models.RecordID, error) {
	row, err := s.getHandle(ctx, handle)
	if err != nil {
		return models.RecordID{}, err
	}
	if row.Kind == OwnerKindOrganization {
		return organizationRecord(handle), nil
	}
	return *row.User, nil
}

// appOwner resolves the owner record of a client to the owner as users see it.
func (s *SurrealStore) appOwner(ctx context.Context, record *models.RecordID) (*Owner, error) {
	if record == nil {
		return nil, ErrNotFound
	}
	if record.Table == "organization" {
		return s.organizationOwner(ctx, recordTail(*record))
	}
	return s.UserOwner(ctx, recordTail(*record))
}

const createAppStatementTemplate = `
	BEGIN TRANSACTION;
	CREATE $client SET %s;
	%s
	COMMIT TRANSACTION;`

const addCreatorGrantsStatement = `UPDATE organization_member SET grants += $creator_grants
	WHERE organization = $owner AND user = $creator;`

// createAppStatement builds the creation of the client and, for organizations,
// the creator's new per-app grants, with their parameters. A public client has
// no secret hash field at all.
func createAppStatement(newApp NewApp, owner models.RecordID) (string, map[string]any) {
	assignments := []string{
		"owner = $owner", "name = $name", "description = $description", "homepage = $homepage",
		"redirect_uris = $redirect_uris", "scopes = $scopes", "scope_reasons = $scope_reasons", "public = $public",
	}
	params := map[string]any{
		"client": clientRecord(newApp.ID), "owner": owner, "name": newApp.Fields.Name,
		"description": newApp.Fields.Description, "homepage": newApp.Fields.Homepage,
		"redirect_uris": newApp.Fields.RedirectURIs, "scopes": ScopeNames(newApp.Fields.Scopes),
		"scope_reasons": scopeReasonRows(newApp.Fields.Scopes), "public": newApp.Type == AppTypePublic,
	}
	if newApp.SecretHash != "" {
		assignments = append(assignments, "secret_hash = $secret_hash")
		params["secret_hash"] = newApp.SecretHash
	}
	grantStatement := ""
	if owner.Table == "organization" && len(newApp.CreatorGrants) > 0 {
		grantStatement = addCreatorGrantsStatement
		params["creator_grants"] = memberGrantRows(newApp.CreatorGrants)
		params["creator"] = userRecord(newApp.CreatorID)
	}
	return fmt.Sprintf(createAppStatementTemplate, strings.Join(assignments, ", "), grantStatement), params
}

// CreateApp registers a third-party client. The client is never first party.
func (s *SurrealStore) CreateApp(ctx context.Context, newApp NewApp) (*App, error) {
	owner, err := s.ownerRecord(ctx, newApp.OwnerHandle)
	if err != nil {
		return nil, err
	}
	statement, params := createAppStatement(newApp, owner)
	if err := queryExec(ctx, s.DB, statement, params); err != nil {
		return nil, fmt.Errorf("create app: %w", err)
	}
	return s.GetApp(ctx, newApp.ID)
}

// GetApp returns a client with its owner; ErrNotFound when it does not exist or
// has no owner, as the seed's sample app.
func (s *SurrealStore) GetApp(ctx context.Context, clientID string) (*App, error) {
	row, err := queryFirst[dbApp](ctx, s.DB, "SELECT * FROM $client", map[string]any{"client": clientRecord(clientID)})
	if err != nil {
		return nil, err
	}
	owner, err := s.appOwner(ctx, row.Owner)
	if err != nil {
		return nil, err
	}
	return row.toApp(*owner), nil
}

// ListApps returns the clients of the owner of handle, oldest first.
func (s *SurrealStore) ListApps(ctx context.Context, handle string) ([]AppSummary, error) {
	owner, err := s.ownerRecord(ctx, handle)
	if err != nil {
		return nil, err
	}
	rows, err := queryRows[dbApp](ctx, s.DB, "SELECT * FROM client WHERE owner = $owner ORDER BY created_at, name",
		map[string]any{"owner": owner})
	if err != nil {
		return nil, fmt.Errorf("list apps: %w", err)
	}
	apps := make([]AppSummary, 0, len(rows))
	for _, row := range rows {
		apps = append(apps, row.summary())
	}
	return apps, nil
}

// AppBelongsTo reports whether the client is owned by the owner of handle.
func (s *SurrealStore) AppBelongsTo(ctx context.Context, clientID string, handle string) (bool, error) {
	owner, err := s.ownerRecord(ctx, handle)
	if err != nil {
		return false, err
	}
	rows, err := queryRows[countRow](ctx, s.DB, "SELECT count() FROM client WHERE id = $client AND owner = $owner GROUP ALL",
		map[string]any{"client": clientRecord(clientID), "owner": owner})
	if err != nil {
		return false, err
	}
	return len(rows) > 0 && rows[0].Count > 0, nil
}

// updateAppStatement builds the update of the fields set in the patch with its
// parameters; assignments is empty when the patch changes nothing.
func updateAppStatement(clientID string, patch AppPatch) (string, map[string]any) {
	assignments := []string{}
	params := map[string]any{"client": clientRecord(clientID)}
	if patch.Name != nil {
		assignments = append(assignments, "name = $name")
		params["name"] = *patch.Name
	}
	if patch.Description != nil {
		assignments = append(assignments, "description = $description")
		params["description"] = *patch.Description
	}
	if patch.Homepage != nil {
		assignments = append(assignments, "homepage = $homepage")
		params["homepage"] = *patch.Homepage
	}
	if patch.RedirectURIs != nil {
		assignments = append(assignments, "redirect_uris = $redirect_uris")
		params["redirect_uris"] = patch.RedirectURIs
	}
	if patch.Scopes != nil {
		assignments = append(assignments, "scopes = $scopes", "scope_reasons = $scope_reasons")
		params["scopes"] = ScopeNames(*patch.Scopes)
		params["scope_reasons"] = scopeReasonRows(*patch.Scopes)
	}
	if len(assignments) == 0 {
		return "", params
	}
	return "UPDATE $client SET " + strings.Join(assignments, ", "), params
}

// UpdateApp applies the patch and returns the app.
func (s *SurrealStore) UpdateApp(ctx context.Context, clientID string, patch AppPatch) (*App, error) {
	statement, params := updateAppStatement(clientID, patch)
	if statement != "" {
		if err := queryExec(ctx, s.DB, statement, params); err != nil {
			return nil, fmt.Errorf("update app: %w", err)
		}
	}
	return s.GetApp(ctx, clientID)
}

// SetAppSecretHash replaces a confidential client's secret hash.
func (s *SurrealStore) SetAppSecretHash(ctx context.Context, clientID string, secretHash string) error {
	return queryExec(ctx, s.DB, "UPDATE $client SET secret_hash = $secret_hash",
		map[string]any{"client": clientRecord(clientID), "secret_hash": secretHash})
}

type dbAppInstall struct {
	ID   models.RecordID `json:"id"`
	User models.RecordID `json:"user"`
}

// revokeAppInstalls revokes every active install of the client, which also
// stops their refresh tokens.
func (s *SurrealStore) revokeAppInstalls(ctx context.Context, clientID string) error {
	installs, err := queryRows[dbAppInstall](ctx, s.DB, "SELECT id, user FROM install WHERE client = $client AND revoked_at = NONE",
		map[string]any{"client": clientRecord(clientID)})
	if err != nil {
		return fmt.Errorf("list app installs: %w", err)
	}
	for _, install := range installs {
		if err := s.RevokeInstall(ctx, recordTail(install.User), recordTail(install.ID)); err != nil {
			return err
		}
	}
	return nil
}

const deleteAppStatement = `
	BEGIN TRANSACTION;
	UPDATE refresh_token SET revoked = true WHERE client = $client;
	DELETE grant WHERE client = $client;
	UPDATE organization_member SET grants = grants.filter(|$entry| $entry.app != $client_id)
		WHERE grants.any(|$entry| $entry.app = $client_id);
	UPDATE organization_invitation SET grants = grants.filter(|$entry| $entry.app != $client_id)
		WHERE grants.any(|$entry| $entry.app = $client_id);
	DELETE $client;
	COMMIT TRANSACTION;`

// DeleteApp revokes the installs and tokens of the client, removes the user
// grants of it and the member and invitation grants that name it, then deletes it.
func (s *SurrealStore) DeleteApp(ctx context.Context, clientID string) error {
	if err := s.revokeAppInstalls(ctx, clientID); err != nil {
		return err
	}
	err := queryExec(ctx, s.DB, deleteAppStatement,
		map[string]any{"client": clientRecord(clientID), "client_id": clientID})
	if err != nil {
		return fmt.Errorf("delete app: %w", err)
	}
	return nil
}

const publishedCollectionsStatement = `
	SELECT VALUE string::concat('@', scope, '/', name) FROM registry_schema
	WHERE string::concat('@', scope, '/', name) IN $collections
		AND (SELECT VALUE descriptor FROM registry_schema_version
			WHERE schema = $parent.id AND version = $parent.latest_version)[0] != NONE`

// PublishedCollections returns those of the collections (`@scope/name`) whose
// latest registry version defines nodes, the check consent makes before it
// creates a root.
func (s *SurrealStore) PublishedCollections(ctx context.Context, collections []string) (map[string]bool, error) {
	published, err := queryRows[string](ctx, s.DB, publishedCollectionsStatement, map[string]any{"collections": collections})
	if err != nil {
		return nil, fmt.Errorf("published collections: %w", err)
	}
	found := make(map[string]bool, len(published))
	for _, collection := range published {
		found[collection] = true
	}
	return found, nil
}
