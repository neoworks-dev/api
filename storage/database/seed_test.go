package database_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/neoworks/auth/storage/database"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

func TestFirstPartyClientsAreSeeded(t *testing.T) {
	f := newFixture(t)
	wanted := map[string][]string{
		"neoworks-calendar":      {"@neoworks/calendar:read", "@neoworks/calendar:write", "@neoworks/calendar:share"},
		"neoworks-contacts":      {"@neoworks/contacts:read", "@neoworks/contacts:write", "@neoworks/contacts:share"},
		"neoworks-photos":        {"@neoworks/photos:read", "@neoworks/photos:write", "@neoworks/photos:share"},
		"neoworks-authenticator": {"openid"},
		"openschema":             {"openid", "schemas:publish"},
	}
	for clientID, scopes := range wanted {
		client, err := f.store.GetClient(context.Background(), clientID)
		if err != nil {
			t.Fatalf("client %s: %v", clientID, err)
		}
		if !client.Public || !client.FirstParty || len(client.RedirectURIs) == 0 {
			t.Errorf("client %s is not a usable public client: %+v", clientID, client)
		}
		for _, scope := range scopes {
			if !slices.Contains(client.Scopes, scope) {
				t.Errorf("client %s lacks scope %s", clientID, scope)
			}
		}
	}
}

func TestTheFilesClientIsNotSeeded(t *testing.T) {
	f := newFixture(t)
	_, err := f.store.GetClient(context.Background(), "neoworks-files")
	if !errors.Is(err, database.ErrNotFound) {
		t.Fatalf("neoworks-files must not be seeded, got %v", err)
	}
}

func TestTheExampleSongsClientIsThirdParty(t *testing.T) {
	f := newFixture(t)
	client, err := f.store.GetClient(context.Background(), "example-songs")
	if err != nil {
		t.Fatal(err)
	}
	if client.FirstParty {
		t.Fatal("example-songs must be a third-party client")
	}
}

func TestFirstPartyCannotBeChangedAfterTheClientExists(t *testing.T) {
	f := newFixture(t)
	results, err := surrealdb.Query[any](context.Background(), f.store.DB,
		"UPDATE $id SET first_party = true", map[string]any{"id": models.NewRecordID("client", "example-songs")})
	if err == nil && len(*results) > 0 && (*results)[0].Error == nil {
		t.Fatal("updating first_party on an existing client must fail")
	}
	client, err := f.store.GetClient(context.Background(), "example-songs")
	if err != nil || client.FirstParty {
		t.Fatalf("example-songs must stay third-party: %+v %v", client, err)
	}
}
