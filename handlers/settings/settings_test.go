package settings_test

import (
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/handlers/handlertest"
	"github.com/neoworks/auth/handlers/settings"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/storage/database/dbtest"
)

func TestSettingsAreScopedToUserAndWrittenByTheOwningClient(t *testing.T) {
	store := dbtest.New(t)
	handler := settings.NewHandler(store)
	router := handlertest.NewAuthenticated(func(router chi.Router) { handler.RegisterAuthenticated(router) })
	user := handlertest.CreateUser(t, store)
	other := handlertest.CreateUser(t, store)
	calendar := map[string]string{"X-Test-Client": "neoworks-calendar"}
	contacts := map[string]string{"X-Test-Client": "neoworks-contacts"}

	if put := router.Do(t, user, "PUT", "/api/v1/settings/theme", map[string]string{"value": `"dark"`}, calendar); put.Code != http.StatusOK {
		t.Fatalf("put: %d %s", put.Code, put.Body.String())
	}
	router.Do(t, user, "PUT", "/api/v1/settings/theme", map[string]string{"value": `"light"`}, calendar)

	var stored database.Setting
	handlertest.Decode(t, router.Do(t, user, "GET", "/api/v1/settings/theme", nil, calendar), &stored)
	if stored.Value != `"light"` || stored.ClientID != "neoworks-calendar" {
		t.Fatalf("upsert should replace: %+v", stored)
	}

	if own := router.Do(t, user, "GET", "/api/v1/settings/theme", nil, contacts); own.Code != http.StatusNotFound {
		t.Fatalf("another client's key without clientId: got %d want 404", own.Code)
	}
	shared := router.Do(t, user, "GET", "/api/v1/settings/theme?clientId=neoworks-calendar", nil, contacts)
	if shared.Code != http.StatusOK {
		t.Fatalf("reading another client's setting: got %d want 200", shared.Code)
	}
	if foreign := router.Do(t, other, "GET", "/api/v1/settings/theme?clientId=neoworks-calendar", nil, calendar); foreign.Code != http.StatusNotFound {
		t.Fatalf("another user's setting: got %d want 404", foreign.Code)
	}

	var list struct {
		Settings []database.Setting `json:"settings"`
	}
	handlertest.Decode(t, router.Do(t, user, "GET", "/api/v1/settings", nil, calendar), &list)
	if len(list.Settings) != 1 {
		t.Fatalf("list: %+v", list)
	}
	if del := router.Do(t, user, "DELETE", "/api/v1/settings/theme", nil, calendar); del.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", del.Code)
	}
	if gone := router.Do(t, user, "GET", "/api/v1/settings/theme", nil, calendar); gone.Code != http.StatusNotFound {
		t.Fatalf("after delete: got %d want 404", gone.Code)
	}
}
