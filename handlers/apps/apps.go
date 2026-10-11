// Package apps serves the registration of OAuth clients by the people and
// organizations that own them: create, list, edit, rotate the secret and
// delete. Every route acts for the signed-in account through the web
// dashboard.
package apps

import (
	"errors"
	"log/slog"
	"net/http"
	"slices"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/handlers/respond"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/ownership"
	"github.com/neoworks/auth/storage/database"
)

const maxRequestBody = 32 << 10

type Handler struct {
	store *database.SurrealStore
}

func NewHandler(store *database.SurrealStore) *Handler {
	return &Handler{store: store}
}

// RegisterAuthenticated mounts the routes. The router must admit only account
// principals of the web dashboard's client: these routes act for the account,
// so an app holding an account token must not reach them.
func (h *Handler) RegisterAuthenticated(router chi.Router) {
	router.Get("/api/v1/owners/{handle}/apps", h.list)
	router.Post("/api/v1/owners/{handle}/apps", h.create)
	router.Get("/api/v1/apps/{clientId}", h.get)
	router.Patch("/api/v1/apps/{clientId}", h.update)
	router.Post("/api/v1/apps/{clientId}/secret", h.rotateSecret)
	router.Delete("/api/v1/apps/{clientId}", h.delete)
}

// appView is an app with what the caller may do with it.
type appView struct {
	database.App
	MyPermissions []ownership.Permission `json:"myPermissions"`
}

func viewOf(app *database.App, grants []ownership.Grant) appView {
	permissions := []ownership.Permission{}
	for _, permission := range ownership.PerAppPermissions {
		if ownership.Allows(grants, permission, app.ID) {
			permissions = append(permissions, permission)
		}
	}
	return appView{App: *app, MyPermissions: permissions}
}

// acting is a request acting for one owner, and for one app when app is set.
type acting struct {
	userID string
	handle string
	grants []ownership.Grant
	app    *database.App
}

func userOf(r *http.Request) string {
	principal, _ := middleware.PrincipalFromContext(r.Context())
	return principal.UserID
}

// ownerOf resolves the owner in the path and the caller's grants for it. The
// owners a caller cannot act for are answered as missing: membership is private.
func (h *Handler) ownerOf(w http.ResponseWriter, r *http.Request) (*acting, bool) {
	userID := userOf(r)
	handle := chi.URLParam(r, "handle")
	grants, err := h.store.GrantsFor(r.Context(), userID, handle)
	if errors.Is(err, database.ErrForbidden) {
		respond.Error(w, http.StatusNotFound, "not_found", "not found")
		return nil, false
	}
	if err != nil {
		respond.StoreError(w, "grantsFor", err)
		return nil, false
	}
	return &acting{userID: userID, handle: handle, grants: grants}, true
}

// appOf resolves the app in the path, its owner and the caller's grants for it.
func (h *Handler) appOf(w http.ResponseWriter, r *http.Request) (*acting, bool) {
	userID := userOf(r)
	app, err := h.store.GetApp(r.Context(), chi.URLParam(r, "clientId"))
	if err != nil {
		respond.StoreError(w, "getApp", err)
		return nil, false
	}
	grants, err := h.store.GrantsFor(r.Context(), userID, app.Owner.Handle)
	if errors.Is(err, database.ErrForbidden) {
		respond.Error(w, http.StatusNotFound, "not_found", "not found")
		return nil, false
	}
	if err != nil {
		respond.StoreError(w, "grantsFor", err)
		return nil, false
	}
	return &acting{userID: userID, handle: app.Owner.Handle, grants: grants, app: app}, true
}

// appID is the app the permission is checked for; empty for the owner as a whole.
func (a *acting) appID() string {
	if a.app == nil {
		return ""
	}
	return a.app.ID
}

// allowed requires the permission at the reach of the acting app (the whole
// owner when there is none) and refuses changes to an archived organization.
func (h *Handler) allowed(w http.ResponseWriter, r *http.Request, a *acting, permission ownership.Permission) bool {
	if !ownership.Allows(a.grants, permission, a.appID()) {
		respond.MissingPermission(w, permission)
		return false
	}
	archived, err := h.store.IsOwnerArchived(r.Context(), a.handle)
	if err != nil {
		respond.StoreError(w, "isOwnerArchived", err)
		return false
	}
	if archived {
		respond.StoreError(w, "allowed", database.ErrArchived)
		return false
	}
	return true
}

// writeFieldError answers a rejected field as 400, and anything else as a store error.
func writeFieldError(w http.ResponseWriter, operation string, err error) {
	var rejected *fieldError
	if !errors.As(err, &rejected) {
		respond.StoreError(w, operation, err)
		return
	}
	respond.JSON(w, http.StatusBadRequest, map[string]string{
		"error": rejected.code, "field": rejected.field, "message": rejected.message,
	})
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.ownerOf(w, r)
	if !ok {
		return
	}
	apps, err := h.store.ListApps(r.Context(), owner.handle)
	if err != nil {
		respond.StoreError(w, "listApps", err)
		return
	}
	respond.JSON(w, http.StatusOK, map[string]any{"apps": apps})
}

type createdApp struct {
	App          appView `json:"app"`
	ClientSecret string  `json:"clientSecret,omitempty"`
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.ownerOf(w, r)
	if !ok || !h.allowed(w, r, owner, ownership.AppsCreate) {
		return
	}
	var request appRequest
	if !respond.Decode(w, r, &request, maxRequestBody) {
		return
	}
	newApp, err := h.newApp(r, owner, request)
	if err != nil {
		writeFieldError(w, "newApp", err)
		return
	}
	app, err := h.store.CreateApp(r.Context(), newApp.NewApp)
	if err != nil {
		respond.StoreError(w, "createApp", err)
		return
	}
	h.auditApp(r, owner, app, database.AuditAppCreated, map[string]any{"type": app.Type})
	grants := append(slices.Clone(owner.grants), newApp.CreatorGrants...)
	respond.JSON(w, http.StatusCreated, createdApp{App: viewOf(app, grants), ClientSecret: newApp.secret})
}

// registration is a validated app to create and, for a confidential one, the
// secret to show once.
type registration struct {
	database.NewApp
	secret string
}

func (h *Handler) newApp(r *http.Request, owner *acting, request appRequest) (registration, error) {
	appType, err := parseType(request)
	if err != nil {
		return registration{}, err
	}
	fields, err := h.validatedFields(r, request)
	if err != nil {
		return registration{}, err
	}
	clientID, err := newClientID()
	if err != nil {
		return registration{}, err
	}
	created := registration{NewApp: database.NewApp{
		ID: clientID, OwnerHandle: owner.handle, CreatorID: owner.userID, Type: appType, Fields: fields,
		CreatorGrants: missingAppGrants(owner.grants, clientID),
	}}
	if appType == database.AppTypePublic {
		return created, nil
	}
	created.secret, created.SecretHash, err = newClientSecret()
	return created, err
}

// validatedFields validates a create body: required fields present, every
// field well formed, requested collections published.
func (h *Handler) validatedFields(r *http.Request, request appRequest) (database.AppFields, error) {
	patch, err := parsePatch(request)
	if err != nil {
		return database.AppFields{}, err
	}
	fields, err := newAppFields(patch)
	if err != nil {
		return database.AppFields{}, err
	}
	if err := checkCollectionsPublished(r.Context(), h.store, fields.Scopes); err != nil {
		return database.AppFields{}, err
	}
	return fields, nil
}

// missingAppGrants are the per-app permissions the creator does not already hold
// organization-wide.
func missingAppGrants(held []ownership.Grant, clientID string) []ownership.Grant {
	missing := []ownership.Grant{}
	for _, permission := range ownership.PerAppPermissions {
		if !ownership.Allows(held, permission, "") {
			missing = append(missing, ownership.ForApp(permission, clientID))
		}
	}
	return missing
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	a, ok := h.appOf(w, r)
	if !ok {
		return
	}
	respond.JSON(w, http.StatusOK, viewOf(a.app, a.grants))
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	a, ok := h.appOf(w, r)
	if !ok || !h.allowed(w, r, a, ownership.AppsEdit) {
		return
	}
	var request appRequest
	if !respond.Decode(w, r, &request, maxRequestBody) {
		return
	}
	patch, err := h.validatedPatch(r, request)
	if err != nil {
		writeFieldError(w, "validatedPatch", err)
		return
	}
	updated, err := h.store.UpdateApp(r.Context(), a.app.ID, patch)
	if err != nil {
		respond.StoreError(w, "updateApp", err)
		return
	}
	h.auditChanges(r, a, updated)
	respond.JSON(w, http.StatusOK, viewOf(updated, a.grants))
}

func (h *Handler) validatedPatch(r *http.Request, request appRequest) (database.AppPatch, error) {
	if request.Type != nil {
		return database.AppPatch{}, invalidField("type", "the type of an app cannot change")
	}
	patch, err := parsePatch(request)
	if err != nil {
		return patch, err
	}
	if patch.Scopes != nil {
		err = checkCollectionsPublished(r.Context(), h.store, *patch.Scopes)
	}
	return patch, err
}

// auditChanges records the redirect URI and scope changes between the app the
// request loaded and the updated one.
func (h *Handler) auditChanges(r *http.Request, a *acting, updated *database.App) {
	if !slices.Equal(a.app.RedirectURIs, updated.RedirectURIs) {
		h.auditApp(r, a, updated, database.AuditAppRedirectURIsChanged,
			map[string]any{"before": a.app.RedirectURIs, "after": updated.RedirectURIs})
	}
	if !slices.Equal(a.app.Scopes, updated.Scopes) {
		h.auditApp(r, a, updated, database.AuditAppScopesChanged,
			map[string]any{"before": database.ScopeNames(a.app.Scopes), "after": database.ScopeNames(updated.Scopes)})
	}
}

func (h *Handler) rotateSecret(w http.ResponseWriter, r *http.Request) {
	a, ok := h.appOf(w, r)
	if !ok || !h.allowed(w, r, a, ownership.AppsSecrets) {
		return
	}
	if a.app.Type != database.AppTypeConfidential {
		writeFieldError(w, "rotateSecret", invalidField("type", "public apps have no client secret"))
		return
	}
	secret, secretHash, err := newClientSecret()
	if err != nil {
		respond.StoreError(w, "newClientSecret", err)
		return
	}
	if err := h.store.SetAppSecretHash(r.Context(), a.app.ID, secretHash); err != nil {
		respond.StoreError(w, "setAppSecretHash", err)
		return
	}
	h.auditApp(r, a, a.app, database.AuditAppSecretRotated, nil)
	respond.JSON(w, http.StatusOK, map[string]string{"clientSecret": secret})
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	a, ok := h.appOf(w, r)
	if !ok || !h.allowed(w, r, a, ownership.AppsDelete) {
		return
	}
	if err := h.store.DeleteApp(r.Context(), a.app.ID); err != nil {
		respond.StoreError(w, "deleteApp", err)
		return
	}
	h.auditApp(r, a, a.app, database.AuditAppDeleted, nil)
	w.WriteHeader(http.StatusNoContent)
}

// auditApp records an action in the organization's audit log; people have none.
// A failure is logged, since the action already happened.
func (h *Handler) auditApp(r *http.Request, a *acting, app *database.App, action string, details map[string]any) {
	if app.Owner.Kind != database.OwnerKindOrganization {
		return
	}
	err := h.store.RecordAudit(r.Context(), database.AuditInput{
		Organization: a.handle, ActorID: a.userID, Action: action,
		Target:  database.AuditTarget{Kind: "app", ID: app.ID, Label: app.Name},
		Details: details,
	})
	if err != nil {
		slog.Error("record app audit", "organization", a.handle, "action", action, "error", err)
	}
}
