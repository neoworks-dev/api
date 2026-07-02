package gql

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/neoworks/auth/config"
	"github.com/neoworks/auth/email"
	gql_model "github.com/neoworks/auth/gql/model"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

type dbOrgInvite struct {
	ID           *models.RecordID `json:"id,omitempty"`
	Organization *models.RecordID `json:"organization,omitempty"`
	Email        string           `json:"email"`
	Role         string           `json:"role"`
	Token        string           `json:"token"`
	Status       string           `json:"status"`
	CreatedAt    time.Time        `json:"created_at"`
	ExpiresAt    time.Time        `json:"expires_at"`
}

func orgInviteToGQL(i *dbOrgInvite) *gql_model.OrgInvite {
	id := ""
	if i.ID != nil {
		id = fmt.Sprintf("%v", i.ID.ID)
	}
	return &gql_model.OrgInvite{
		ID:        id,
		Email:     i.Email,
		Role:      i.Role,
		Status:    i.Status,
		CreatedAt: i.CreatedAt.String(),
		ExpiresAt: i.ExpiresAt.String(),
	}
}

func firstOrgInvite(results *[]surrealdb.QueryResult[[]dbOrgInvite]) *dbOrgInvite {
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			invite := qr.Result[0]
			return &invite
		}
	}
	return nil
}

func newInviteToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// userEmail returns the email address for a user id, or "" when not found.
func userEmail(ctx context.Context, db *surrealdb.DB, userID string) string {
	results, err := surrealdb.Query[[]struct {
		Email string `json:"email"`
	}](ctx, db, "SELECT email FROM $user", map[string]any{"user": models.NewRecordID("user", userID)})
	if err != nil {
		return ""
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return qr.Result[0].Email
		}
	}
	return ""
}

// inviteAcceptURL builds the link the recipient follows to accept an invite.
func inviteAcceptURL(token string) string {
	base := os.Getenv("APP_WEB_URL")
	if base == "" {
		base = config.ServiceURL("")
	}
	return strings.TrimRight(base, "/") + "/invites/" + token
}

// sendInviteEmail emails an organization invitation link. Kept here (not in a
// *.resolvers.go file) so gqlgen codegen doesn't relocate it.
func (r *mutationResolver) sendInviteEmail(ctx context.Context, to, token string) {
	acceptURL := inviteAcceptURL(token)
	msg := email.Message{
		To:      []string{to},
		Subject: "You've been invited to a Neoworks organization",
		Text:    fmt.Sprintf("You've been invited to join a Neoworks organization.\n\nAccept your invitation:\n%s\n", acceptURL),
	}
	_ = r.mailer.Send(ctx, msg)
}
