package dataplane

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/gqlerrors"
	"github.com/graphql-go/graphql/language/ast"
	"github.com/graphql-go/graphql/language/parser"
	"github.com/graphql-go/graphql/language/source"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/storage/database"
)

type graphQLRequest struct {
	Query         string         `json:"query"`
	OperationName string         `json:"operationName"`
	Variables     map[string]any `json:"variables"`
}

// Handler returns the HTTP handler for the per-database data plane, served at
// /graphql/db/{clientId}/{dbName}. Mounted publicly: schema INTROSPECTION is open
// to anyone (so clients can codegen typed clients), but DATA operations require a
// valid bearer token whose client_id matches the path and are scoped to that user.
func (e *Engine) Handler(auth *middleware.ClientAuth) http.Handler {
	debug := os.Getenv("DATAPLANE_DEBUG") == "1"

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientID := chi.URLParam(r, "clientId")
		name := chi.URLParam(r, "dbName")

		compiled, err := e.schemaFor(r.Context(), clientID, name)
		if err != nil {
			if errors.Is(err, errDatabaseNotFound) {
				writeError(w, http.StatusNotFound, "database not found")
				return
			}
			slog.Error("dataplane schema build", "error", err, "client", clientID, "db", name)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		var req graphQLRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		// Introspection is public. Mutations always require a valid tenant token.
		// Read queries are token-optional: anonymous callers see only public rows.
		// A token that IS supplied must still be valid, so an expired token fails
		// loudly rather than silently degrading to an anonymous read.
		//
		// A token with no user subject is a client_credentials token — the client
		// acting as its own organization, which is what authorizes org-scoped writes.
		uid := ""
		clientPrincipal := false
		if !isIntrospectionOnly(req.Query) {
			requireAuth := containsMutation(req.Query) || r.Header.Get("Authorization") != ""
			if requireAuth {
				claim := verifyBearer(r, auth)
				if claim == nil {
					writeError(w, http.StatusUnauthorized, "unauthorized")
					return
				}
				if claim.ClientID != clientID {
					writeError(w, http.StatusForbidden, "forbidden")
					return
				}
				uid = claim.Subject
				clientPrincipal = claim.Subject == ""
			}
		}

		ctx := withRequest(r.Context(), requestInfo{
			uid:             uid,
			namespace:       compiled.namespace,
			dbName:          compiled.physicalDB,
			clientOrg:       compiled.clientOrg,
			clientPrincipal: clientPrincipal,
		})
		result := graphql.Do(graphql.Params{
			Schema:         compiled.schema,
			RequestString:  req.Query,
			VariableValues: req.Variables,
			OperationName:  req.OperationName,
			Context:        ctx,
		})

		// A tenant that hit its concurrency cap is a retryable backpressure signal,
		// not a query error — surface it as 429 so clients back off.
		if tenantBusy(result.Errors) {
			writeError(w, http.StatusTooManyRequests, "database busy, retry shortly")
			return
		}

		// Scrub resolver/internal errors: log server-side, return a generic
		// message unless DATAPLANE_DEBUG is set (dev convenience).
		if len(result.Errors) > 0 && !debug {
			for _, ge := range result.Errors {
				slog.Error("dataplane query error", "error", ge.Message, "path", ge.Path, "client", clientID, "db", name)
				ge.Message = "query error"
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	})
}

// tenantBusy reports whether any resolver error is a throttle rejection. It checks
// the unwrapped original error and falls back to the message, since graphql-go does
// not always preserve the error wrap chain.
func tenantBusy(errs []gqlerrors.FormattedError) bool {
	for _, ge := range errs {
		if errors.Is(ge.OriginalError(), database.ErrTenantBusy) {
			return true
		}
		if ge.Message == database.ErrTenantBusy.Error() {
			return true
		}
	}
	return false
}

// verifyBearer extracts and validates the Authorization bearer token, or returns
// nil if absent/invalid.
func verifyBearer(r *http.Request, auth *middleware.ClientAuth) *oauth.Claims {
	h := r.Header.Get("Authorization")
	if len(h) < 8 || !strings.EqualFold(h[:7], "Bearer ") {
		return nil
	}
	claim, err := auth.Verify(r.Context(), h[7:])
	if err != nil {
		return nil
	}
	return claim
}

// isIntrospectionOnly reports whether every top-level field of every query
// operation is an introspection meta-field (__schema/__type/__typename), so the
// request reveals only schema shape and no user data.
func isIntrospectionOnly(query string) bool {
	doc, err := parser.Parse(parser.ParseParams{Source: source.NewSource(&source.Source{Body: []byte(query)})})
	if err != nil {
		return false
	}
	sawOp := false
	for _, def := range doc.Definitions {
		op, ok := def.(*ast.OperationDefinition)
		if !ok {
			continue
		}
		sawOp = true
		if op.Operation != ast.OperationTypeQuery {
			return false // mutations/subscriptions are never introspection
		}
		if op.SelectionSet == nil {
			return false
		}
		for _, sel := range op.SelectionSet.Selections {
			field, ok := sel.(*ast.Field)
			if !ok || field.Name == nil || !strings.HasPrefix(field.Name.Value, "__") {
				return false
			}
		}
	}
	return sawOp
}

// containsMutation reports whether the request contains any mutation operation.
// An unparseable query is treated as a mutation (fail safe → require auth).
func containsMutation(query string) bool {
	doc, err := parser.Parse(parser.ParseParams{Source: source.NewSource(&source.Source{Body: []byte(query)})})
	if err != nil {
		return true
	}
	for _, def := range doc.Definitions {
		op, ok := def.(*ast.OperationDefinition)
		if !ok {
			continue
		}
		if op.Operation == ast.OperationTypeMutation {
			return true
		}
	}
	return false
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
