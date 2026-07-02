package database

import (
	"context"
	"fmt"
	"strings"

	gql_model "github.com/neoworks/auth/gql/model"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

type ConnectionStore struct {
	DB *surrealdb.DB
}

// dbUserProfile is the raw user row used to project a ConnectionProfile.
type dbUserProfile struct {
	ID        *models.RecordID `json:"id,omitempty"`
	FirstName string           `json:"first_name"`
	LastName  string           `json:"last_name"`
	Email     *string          `json:"email,omitempty"`
}

func recordIDString(r *models.RecordID) string {
	if r == nil {
		return ""
	}
	return fmt.Sprintf("%v", r.ID)
}

// profileWithGrant builds a ConnectionProfile, populating consented fields only.
func profileWithGrant(u *dbUserProfile, granted []string) *gql_model.ConnectionProfile {
	p := &gql_model.ConnectionProfile{
		ID:        recordIDString(u.ID),
		FirstName: u.FirstName,
		LastName:  u.LastName,
	}
	for _, f := range granted {
		if f == "email" {
			p.Email = u.Email
		}
	}
	return p
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// IsConnected reports whether two users share an accepted connection.
func (store *ConnectionStore) IsConnected(ctx context.Context, a, b models.RecordID) bool {
	results, err := surrealdb.Query[[]dbConnEdge](ctx, store.DB,
		`SELECT status FROM connection
		 WHERE ((in = $a AND out = $b) OR (in = $b AND out = $a)) AND status = "accepted" LIMIT 1`,
		map[string]any{"a": a, "b": b},
	)
	if err != nil {
		return false
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return true
		}
	}
	return false
}

type dbConnEdge struct {
	In        *models.RecordID `json:"in,omitempty"`
	Out       *models.RecordID `json:"out,omitempty"`
	Other     *models.RecordID `json:"other,omitempty"`
	Direction string           `json:"direction,omitempty"`
	Status    string           `json:"status"`
	CreatedAt string           `json:"created_at,omitempty"`
}

// existingEdge returns the edge between two users in either direction, or nil.
func (store *ConnectionStore) existingEdge(ctx context.Context, a, b models.RecordID) (*dbConnEdge, error) {
	results, err := surrealdb.Query[[]dbConnEdge](ctx, store.DB,
		`SELECT in, out, status, <string>created_at AS created_at FROM connection
		 WHERE (in = $a AND out = $b) OR (in = $b AND out = $a) LIMIT 1`,
		map[string]any{"a": a, "b": b},
	)
	if err != nil {
		return nil, err
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return &qr.Result[0], nil
		}
	}
	return nil, nil
}

func (store *ConnectionStore) profile(ctx context.Context, id models.RecordID) (*dbUserProfile, error) {
	results, err := surrealdb.Query[[]dbUserProfile](ctx, store.DB,
		"SELECT id, first_name, last_name, email FROM user WHERE id = $id LIMIT 1",
		map[string]any{"id": id},
	)
	if err != nil {
		return nil, err
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return &qr.Result[0], nil
		}
	}
	return nil, ErrNotFound
}

func (store *ConnectionStore) toConnection(ctx context.Context, me, other models.RecordID, status, direction, createdAt string) (*gql_model.Connection, error) {
	prof, err := store.profile(ctx, other)
	if err != nil {
		return nil, err
	}
	granted, _ := store.GrantedFields(ctx, other, me)
	return &gql_model.Connection{
		User:      profileWithGrant(prof, granted),
		Status:    status,
		Direction: direction,
		CreatedAt: createdAt,
	}, nil
}

// SendRequest creates (or returns the existing) connection edge. Idempotent for
// pending/accepted; refused for a blocking edge without revealing the block.
func (store *ConnectionStore) SendRequest(ctx context.Context, me, other models.RecordID) (*gql_model.Connection, error) {
	if me == other {
		return nil, fmt.Errorf("cannot connect to yourself")
	}
	edge, err := store.existingEdge(ctx, me, other)
	if err != nil {
		return nil, err
	}
	if edge != nil {
		if edge.Status == "blocked" {
			return nil, fmt.Errorf("cannot send request")
		}
		direction := "outgoing"
		if recordIDString(edge.In) == recordIDString(&other) {
			direction = "incoming"
		}
		return store.toConnection(ctx, me, other, edge.Status, direction, edge.CreatedAt)
	}
	if _, err := surrealdb.Query[[]any](ctx, store.DB,
		`RELATE $me->connection->$other SET status = "pending"`,
		map[string]any{"me": me, "other": other},
	); err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	return store.toConnection(ctx, me, other, "pending", "outgoing", "")
}

// Respond accepts or declines an incoming pending request. Only the addressee
// (out = caller) may respond. Decline deletes the edge and returns nil.
func (store *ConnectionStore) Respond(ctx context.Context, me, requester models.RecordID, accept bool) (*gql_model.Connection, error) {
	if !accept {
		_, err := surrealdb.Query[[]any](ctx, store.DB,
			`DELETE connection WHERE in = $requester AND out = $me AND status = "pending"`,
			map[string]any{"requester": requester, "me": me},
		)
		return nil, err
	}
	results, err := surrealdb.Query[[]struct {
		Status string `json:"status"`
	}](ctx, store.DB,
		`UPDATE connection SET status = "accepted"
		 WHERE in = $requester AND out = $me AND status = "pending" RETURN status`,
		map[string]any{"requester": requester, "me": me},
	)
	if err != nil {
		return nil, fmt.Errorf("respond: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return store.toConnection(ctx, me, requester, "accepted", "incoming", "")
		}
	}
	return nil, ErrNotFound
}

// Remove deletes the connection and any sharing grants between the two users.
func (store *ConnectionStore) Remove(ctx context.Context, me, other models.RecordID) error {
	_, err := surrealdb.Query[[]any](ctx, store.DB,
		`BEGIN TRANSACTION;
		 DELETE connection WHERE (in = $me AND out = $other) OR (in = $other AND out = $me);
		 DELETE sharing_grant WHERE (in = $me AND out = $other) OR (in = $other AND out = $me);
		 COMMIT TRANSACTION;`,
		map[string]any{"me": me, "other": other},
	)
	return err
}

// Block removes any existing edges/grants and records a blocking edge.
func (store *ConnectionStore) Block(ctx context.Context, me, other models.RecordID) (*gql_model.Connection, error) {
	if me == other {
		return nil, fmt.Errorf("cannot block yourself")
	}
	if _, err := surrealdb.Query[[]any](ctx, store.DB,
		`BEGIN TRANSACTION;
		 DELETE connection WHERE (in = $me AND out = $other) OR (in = $other AND out = $me);
		 DELETE sharing_grant WHERE (in = $me AND out = $other) OR (in = $other AND out = $me);
		 RELATE $me->connection->$other SET status = "blocked";
		 COMMIT TRANSACTION;`,
		map[string]any{"me": me, "other": other},
	); err != nil {
		return nil, fmt.Errorf("block: %w", err)
	}
	return store.toConnection(ctx, me, other, "blocked", "outgoing", "")
}

// ListConnections returns the caller's connections (excluding blocked), with the
// "other" user resolved to a consent-aware profile.
func (store *ConnectionStore) ListConnections(ctx context.Context, me models.RecordID, status *string) ([]*gql_model.Connection, error) {
	conditions := `(in = $me OR out = $me) AND status != "blocked"`
	params := map[string]any{"me": me}
	if status != nil {
		conditions += " AND status = $status"
		params["status"] = *status
	}
	query := fmt.Sprintf(
		`SELECT (IF in = $me THEN out ELSE in END) AS other,
		        (IF in = $me THEN "outgoing" ELSE "incoming" END) AS direction,
		        status, <string>created_at AS created_at
		 FROM connection WHERE %s ORDER BY created_at DESC`, conditions)
	results, err := surrealdb.Query[[]dbConnEdge](ctx, store.DB, query, params)
	if err != nil {
		return nil, fmt.Errorf("list connections: %w", err)
	}

	var out []*gql_model.Connection
	for _, qr := range *results {
		for i := range qr.Result {
			row := qr.Result[i]
			if row.Other == nil {
				continue
			}
			conn, err := store.toConnection(ctx, me, *row.Other, row.Status, row.Direction, row.CreatedAt)
			if err != nil {
				continue
			}
			out = append(out, conn)
		}
	}
	return out, nil
}

// SearchUsers finds users by name prefix or exact email for inviting. Excludes
// the caller and anyone with a blocking edge to the caller.
func (store *ConnectionStore) SearchUsers(ctx context.Context, me models.RecordID, query string, limit int) ([]*gql_model.UserSearchResult, error) {
	q := strings.ToLower(strings.TrimSpace(query))
	if len(q) < 2 {
		return nil, nil
	}
	if limit <= 0 || limit > 20 {
		limit = 20
	}
	results, err := surrealdb.Query[[]dbUserProfile](ctx, store.DB,
		`SELECT id, first_name, last_name FROM user
		 WHERE id != $me
		   AND (string::starts_with(string::lowercase(first_name), $q)
		     OR string::starts_with(string::lowercase(last_name), $q)
		     OR email = $exact)
		   AND id NOTINSIDE (SELECT VALUE in FROM connection WHERE out = $me AND status = "blocked")
		 ORDER BY first_name ASC LIMIT $limit`,
		map[string]any{"me": me, "q": q, "exact": strings.TrimSpace(query), "limit": limit},
	)
	if err != nil {
		return nil, fmt.Errorf("search users: %w", err)
	}

	statuses, _ := store.statusMap(ctx, me)
	var out []*gql_model.UserSearchResult
	for _, qr := range *results {
		for i := range qr.Result {
			u := qr.Result[i]
			id := recordIDString(u.ID)
			res := &gql_model.UserSearchResult{ID: id, FirstName: u.FirstName, LastName: u.LastName}
			if s, ok := statuses[id]; ok {
				res.ConnectionStatus = &s
			}
			out = append(out, res)
		}
	}
	return out, nil
}

// statusMap returns otherUserID -> connection status for all of the caller's edges.
func (store *ConnectionStore) statusMap(ctx context.Context, me models.RecordID) (map[string]string, error) {
	results, err := surrealdb.Query[[]dbConnEdge](ctx, store.DB,
		`SELECT (IF in = $me THEN out ELSE in END) AS other, status
		 FROM connection WHERE in = $me OR out = $me`,
		map[string]any{"me": me},
	)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, qr := range *results {
		for i := range qr.Result {
			if qr.Result[i].Other != nil {
				out[recordIDString(qr.Result[i].Other)] = qr.Result[i].Status
			}
		}
	}
	return out, nil
}

// ConnectionProfile resolves a user id to the profile the caller may see. Returns
// nil when the users are not accepted connections.
func (store *ConnectionStore) ConnectionProfile(ctx context.Context, me, target models.RecordID) (*gql_model.ConnectionProfile, error) {
	if !store.IsConnected(ctx, me, target) {
		return nil, nil
	}
	prof, err := store.profile(ctx, target)
	if err != nil {
		return nil, err
	}
	granted, _ := store.GrantedFields(ctx, target, me)
	return profileWithGrant(prof, granted), nil
}

type dbGrant struct {
	In     *models.RecordID `json:"in,omitempty"`
	Out    *models.RecordID `json:"out,omitempty"`
	Fields []string         `json:"fields"`
}

// GrantedFields returns the extra profile fields `owner` shares with `viewer`.
func (store *ConnectionStore) GrantedFields(ctx context.Context, owner, viewer models.RecordID) ([]string, error) {
	results, err := surrealdb.Query[[]dbGrant](ctx, store.DB,
		"SELECT fields FROM sharing_grant WHERE in = $owner AND out = $viewer LIMIT 1",
		map[string]any{"owner": owner, "viewer": viewer},
	)
	if err != nil {
		return nil, err
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return qr.Result[0].Fields, nil
		}
	}
	return nil, nil
}

var allowedShareFields = []string{"email", "phone", "avatar_url"}

// UpsertGrant sets exactly which extra fields the owner shares with the viewer.
// Requires an accepted connection.
func (store *ConnectionStore) UpsertGrant(ctx context.Context, owner, viewer models.RecordID, fields []string) (*gql_model.SharingGrant, error) {
	if !store.IsConnected(ctx, owner, viewer) {
		return nil, fmt.Errorf("not connected")
	}
	for _, f := range fields {
		if !contains(allowedShareFields, f) {
			return nil, fmt.Errorf("invalid share field: %s", f)
		}
	}
	// Replace any existing grant for this pair. An empty field list revokes all
	// extra sharing (the edge is simply removed).
	if _, err := surrealdb.Query[[]any](ctx, store.DB,
		`DELETE sharing_grant WHERE in = $owner AND out = $viewer`,
		map[string]any{"owner": owner, "viewer": viewer},
	); err != nil {
		return nil, fmt.Errorf("upsert grant: %w", err)
	}
	if len(fields) > 0 {
		if _, err := surrealdb.Query[[]any](ctx, store.DB,
			`RELATE $owner->sharing_grant->$viewer SET fields = $fields`,
			map[string]any{"owner": owner, "viewer": viewer, "fields": fields},
		); err != nil {
			return nil, fmt.Errorf("upsert grant: %w", err)
		}
	}
	prof, err := store.profile(ctx, viewer)
	if err != nil {
		return nil, err
	}
	return &gql_model.SharingGrant{
		Viewer: &gql_model.ConnectionProfile{ID: recordIDString(prof.ID), FirstName: prof.FirstName, LastName: prof.LastName},
		Fields: fields,
	}, nil
}

// ListGrants returns the grants the caller has issued.
func (store *ConnectionStore) ListGrants(ctx context.Context, me models.RecordID) ([]*gql_model.SharingGrant, error) {
	results, err := surrealdb.Query[[]dbGrant](ctx, store.DB,
		"SELECT out, fields FROM sharing_grant WHERE in = $me",
		map[string]any{"me": me},
	)
	if err != nil {
		return nil, fmt.Errorf("list grants: %w", err)
	}
	var out []*gql_model.SharingGrant
	for _, qr := range *results {
		for i := range qr.Result {
			g := qr.Result[i]
			if g.Out == nil {
				continue
			}
			prof, err := store.profile(ctx, *g.Out)
			if err != nil {
				continue
			}
			out = append(out, &gql_model.SharingGrant{
				Viewer: &gql_model.ConnectionProfile{ID: recordIDString(prof.ID), FirstName: prof.FirstName, LastName: prof.LastName},
				Fields: g.Fields,
			})
		}
	}
	return out, nil
}

type dbInvitePolicy struct {
	Out    *models.RecordID `json:"out,omitempty"`
	Policy string           `json:"policy"`
}

// SetInvitePolicy sets how `me` handles calendar invites from `other`. A policy of
// "block" or "auto_accept" upserts the edge; anything else (e.g. "default") clears it.
func (store *ConnectionStore) SetInvitePolicy(ctx context.Context, me, other models.RecordID, policy string) error {
	if _, err := surrealdb.Query[[]any](ctx, store.DB,
		`DELETE invite_policy WHERE in = $me AND out = $other`,
		map[string]any{"me": me, "other": other},
	); err != nil {
		return fmt.Errorf("set invite policy: %w", err)
	}
	if policy == "block" || policy == "auto_accept" {
		if _, err := surrealdb.Query[[]any](ctx, store.DB,
			`RELATE $me->invite_policy->$other SET policy = $policy`,
			map[string]any{"me": me, "other": other, "policy": policy},
		); err != nil {
			return fmt.Errorf("set invite policy: %w", err)
		}
	}
	return nil
}

// ListInvitePolicies returns the caller's non-default invite policies.
func (store *ConnectionStore) ListInvitePolicies(ctx context.Context, me models.RecordID) ([]*gql_model.InvitePolicy, error) {
	results, err := surrealdb.Query[[]dbInvitePolicy](ctx, store.DB,
		"SELECT out, policy FROM invite_policy WHERE in = $me",
		map[string]any{"me": me},
	)
	if err != nil {
		return nil, fmt.Errorf("list invite policies: %w", err)
	}
	var out []*gql_model.InvitePolicy
	for _, qr := range *results {
		for i := range qr.Result {
			p := qr.Result[i]
			if p.Out == nil {
				continue
			}
			prof, err := store.profile(ctx, *p.Out)
			if err != nil {
				continue
			}
			out = append(out, &gql_model.InvitePolicy{
				User:   &gql_model.ConnectionProfile{ID: recordIDString(prof.ID), FirstName: prof.FirstName, LastName: prof.LastName},
				Policy: p.Policy,
			})
		}
	}
	return out, nil
}

// InvitePoliciesToward returns, for each invitee in `users`, that invitee's policy
// toward `sender` ("block" | "auto_accept"); absent means default. Keyed by the
// bare user id. Used by the calendar invite path.
func (store *ConnectionStore) InvitePoliciesToward(ctx context.Context, sender models.RecordID, users []string) (map[string]string, error) {
	out := map[string]string{}
	if len(users) == 0 {
		return out, nil
	}
	refs := make([]models.RecordID, len(users))
	for i, id := range users {
		refs[i] = models.NewRecordID("user", id)
	}
	results, err := surrealdb.Query[[]struct {
		In     models.RecordID `json:"in"`
		Policy string          `json:"policy"`
	}](ctx, store.DB,
		"SELECT in, policy FROM invite_policy WHERE out = $sender AND in IN $users",
		map[string]any{"sender": sender, "users": refs},
	)
	if err != nil {
		return nil, fmt.Errorf("invite policies toward: %w", err)
	}
	for _, qr := range *results {
		for _, row := range qr.Result {
			out[fmt.Sprintf("%v", row.In.ID)] = row.Policy
		}
	}
	return out, nil
}
