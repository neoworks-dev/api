package dataplane

import "context"

type contextKey string

const (
	uidContextKey       contextKey = "dataplane.uid"
	namespaceContextKey contextKey = "dataplane.namespace"
	dbNameContextKey    contextKey = "dataplane.dbName"
	clientOrgContextKey contextKey = "dataplane.clientOrg"
	principalContextKey contextKey = "dataplane.clientPrincipal"
)

// requestInfo is the per-request principal/context threaded through graphql.Do
// into the generic resolvers.
//   - uid: authenticated user subject ("" when anonymous or a client-principal token).
//   - namespace: per-client SurrealDB namespace (client_{clientID}).
//   - dbName: client database name within that namespace.
//   - clientOrg: organization that owns the request's client (always known, even
//     anonymously, since the client is in the URL). Owns org-scoped rows.
//   - clientPrincipal: the token is a client_credentials token (client_id set, no
//     user sub) — the client acting as its org. Required for org-scoped writes.
type requestInfo struct {
	uid             string
	namespace       string
	dbName          string
	clientOrg       string
	clientPrincipal bool
}

func withRequest(ctx context.Context, info requestInfo) context.Context {
	ctx = context.WithValue(ctx, uidContextKey, info.uid)
	ctx = context.WithValue(ctx, namespaceContextKey, info.namespace)
	ctx = context.WithValue(ctx, dbNameContextKey, info.dbName)
	ctx = context.WithValue(ctx, clientOrgContextKey, info.clientOrg)
	ctx = context.WithValue(ctx, principalContextKey, info.clientPrincipal)
	return ctx
}

func uidFromContext(ctx context.Context) string {
	uid, _ := ctx.Value(uidContextKey).(string)
	return uid
}

func namespaceFromContext(ctx context.Context) string {
	ns, _ := ctx.Value(namespaceContextKey).(string)
	return ns
}

func dbNameFromContext(ctx context.Context) string {
	name, _ := ctx.Value(dbNameContextKey).(string)
	return name
}

func clientOrgFromContext(ctx context.Context) string {
	org, _ := ctx.Value(clientOrgContextKey).(string)
	return org
}

func clientPrincipalFromContext(ctx context.Context) bool {
	p, _ := ctx.Value(principalContextKey).(bool)
	return p
}

// authedFromContext reports whether the request carries any valid principal — a
// user (uid) or the client itself (client_credentials). Anonymous reads have
// neither and may see only public rows.
func authedFromContext(ctx context.Context) bool {
	return uidFromContext(ctx) != "" || clientPrincipalFromContext(ctx)
}
