package database_test

import (
	"context"
	"slices"
	"testing"
)

func TestFirstPartyClientsAreSeeded(t *testing.T) {
	f := newFixture(t)
	wanted := map[string][]string{
		"neoworks-calendar":      {"@neoworks/calendar:read", "@neoworks/calendar:write", "@neoworks/calendar:share"},
		"neoworks-contacts":      {"@neoworks/contacts:read", "@neoworks/contacts:write", "@neoworks/contacts:share"},
		"neoworks-photos":        {"@neoworks/photos:read", "@neoworks/photos:write", "@neoworks/photos:share"},
		"neoworks-files":         {"@neoworks/files:read", "@neoworks/files:write", "@neoworks/files:share"},
		"neoworks-authenticator": {"openid"},
		"openschema":             {"openid", "schemas:publish"},
	}
	for clientID, scopes := range wanted {
		client, err := f.store.GetClient(context.Background(), clientID)
		if err != nil {
			t.Fatalf("client %s: %v", clientID, err)
		}
		if !client.Public || !client.AutoGrantScopes || len(client.RedirectURIs) == 0 {
			t.Errorf("client %s is not a usable public client: %+v", clientID, client)
		}
		for _, scope := range scopes {
			if !slices.Contains(client.Scopes, scope) {
				t.Errorf("client %s lacks scope %s", clientID, scope)
			}
		}
	}
}
