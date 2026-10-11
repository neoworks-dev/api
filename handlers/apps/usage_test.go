package apps_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/neoworks/auth/handlers/apps"
	"github.com/neoworks/auth/ownership"
	"github.com/neoworks/auth/ratelimit"
	"github.com/neoworks/auth/storage/database"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

type fixedUsage struct{ perDay map[string]ratelimit.DayCount }

func (usage fixedUsage) Record(context.Context, string, bool) error { return nil }

func (usage fixedUsage) Daily(_ context.Context, _ string, days int) ([]ratelimit.DayCount, error) {
	counts := make([]ratelimit.DayCount, 0, days)
	for offset := days - 1; offset >= 0; offset-- {
		date := time.Now().UTC().AddDate(0, 0, -offset).Format("2006-01-02")
		count := usage.perDay[date]
		count.Date = date
		counts = append(counts, count)
	}
	return counts, nil
}

func (f *fixture) authorizeUser(clientID string, installs int) {
	f.t.Helper()
	user := f.userWithHandle("u" + uuid.NewString()[:8])
	_, queryErr := surrealdb.Query[[]any](context.Background(), f.store.DB, "UPSERT grant SET user = $user, client = $client, scopes = [], enabled = true WHERE user = $user AND client = $client",
		map[string]any{"user": models.NewRecordID("user", user.UserID), "client": models.NewRecordID("client", clientID)})
	if queryErr != nil {
		f.t.Fatal(queryErr)
	}
	for range installs {
		_, installErr := f.store.CreateInstall(context.Background(), database.CreateInstallParams{
			InstallID: uuid.NewString(), UserID: user.UserID, ClientID: clientID, EncPub: "e", SignPub: "s", Name: "Phone",
		})
		if installErr != nil {
			f.t.Fatal(installErr)
		}
	}
}

func TestUsageReportsAggregatesOnly(t *testing.T) {
	today := time.Now().UTC().Format("2006-01-02")
	counts := fixedUsage{perDay: map[string]ratelimit.DayCount{today: {Requests: 1200, RateLimited: 7}}}
	f := newFixtureWith(t, func(handler *apps.Handler) { handler.WithUsage(counts) })
	owner := f.userWithHandle("moritz")
	clientID := appOf(f.createApp(owner, "moritz", nil))["id"].(string)
	f.authorizeUser(clientID, 2)
	f.authorizeUser(clientID, 1)

	report := f.expect(owner, "GET", "/api/v1/apps/"+clientID+"/usage?days=7", nil, http.StatusOK, "")
	totals := report["totals"].(map[string]any)
	if totals["authorizedUsers"] != float64(2) || totals["activeInstalls"] != float64(3) || totals["requests"] != float64(1200) || totals["rateLimited"] != float64(7) {
		t.Fatalf("totals: %v", totals)
	}
	series := report["series"].([]any)
	last := series[len(series)-1].(map[string]any)
	if len(series) != 7 || last["date"] != today || last["authorizedUsers"] != float64(2) || last["requests"] != float64(1200) {
		t.Fatalf("series: %v", series)
	}
	for key := range last {
		switch key {
		case "date", "authorizedUsers", "activeInstalls", "requests", "rateLimited":
		default:
			t.Fatalf("unexpected field %q in a usage point", key)
		}
	}
}

func TestUsageNeedsUsageViewAndAValidWindow(t *testing.T) {
	f := newFixture(t)
	leader := f.userWithHandle("founder")
	f.organization("acme", leader)
	clientID := appOf(f.createApp(leader, "acme", nil))["id"].(string)
	editor := f.member("acme", ownership.OrganizationWide(ownership.AppsEdit))

	f.expect(editor, "GET", "/api/v1/apps/"+clientID+"/usage", nil, http.StatusForbidden, "missing_permission")
	f.expect(leader, "GET", "/api/v1/apps/"+clientID+"/usage?days=0", nil, http.StatusBadRequest, "invalid_request")
	f.expect(leader, "GET", "/api/v1/apps/"+clientID+"/usage?days=500", nil, http.StatusBadRequest, "invalid_request")
	report := f.expect(leader, "GET", "/api/v1/apps/"+clientID+"/usage", nil, http.StatusOK, "")
	if len(report["series"].([]any)) != 30 {
		t.Fatalf("the default window is 30 days: %d", len(report["series"].([]any)))
	}
}
