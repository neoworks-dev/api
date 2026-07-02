package gql

import (
	"fmt"
	"time"

	gql_model "github.com/neoworks/auth/gql/model"
	"github.com/neoworks/auth/oauth"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

type dbRefreshTokenFetched struct {
	ID        *models.RecordID `json:"id"`
	Client    *oauth.Client    `json:"client"`
	Scopes    []string         `json:"scopes"`
	ExpiresAt time.Time        `json:"expires_at"`
	CreatedAt time.Time        `json:"created_at"`
	Revoked   bool             `json:"revoked"`
	Used      bool             `json:"used"`
}

func clientDBToGQL(d *oauth.ClientDatabase) *gql_model.ClientDatabase {
	id := ""
	if d.ID != nil {
		id = fmt.Sprintf("%v", d.ID.ID)
	}
	clientID := ""
	if d.Client != nil {
		clientID = fmt.Sprintf("%v", d.Client.ID)
	}
	return &gql_model.ClientDatabase{
		ID:        id,
		ClientID:  clientID,
		Name:      d.Name,
		DbName:    d.DbName,
		Status:    d.Status,
		CreatedAt: d.CreatedAt.String(),
		UpdatedAt: d.UpdatedAt.String(),
	}
}

func oauthClientToGQL(c *oauth.Client) *gql_model.OAuthClient {
	id := ""
	if c.ID != nil {
		id = fmt.Sprintf("%v", c.ID.ID)
	}
	return &gql_model.OAuthClient{
		ID:              id,
		Name:            c.Name,
		Scopes:          c.Scopes,
		RedirectUris:    c.RedirectURIs,
		Public:          c.Public,
		AutoGrantScopes: c.AutoGrantScopes,
	}
}

