package apps

import (
	"net/http"
	"strconv"
	"time"

	"github.com/neoworks/auth/handlers/respond"
	"github.com/neoworks/auth/ownership"
	"github.com/neoworks/auth/ratelimit"
	"github.com/neoworks/auth/storage/database"
)

const (
	defaultUsageDays = 30
	// maxUsageDays is how far back the request counters reach.
	maxUsageDays = 45
)

type usageTotals struct {
	AuthorizedUsers int   `json:"authorizedUsers"`
	ActiveInstalls  int   `json:"activeInstalls"`
	StorageBytes    int64 `json:"storageBytes"`
	Requests        int64 `json:"requests"`
	RateLimited     int64 `json:"rateLimited"`
}

type usagePoint struct {
	Date            string `json:"date"`
	AuthorizedUsers int    `json:"authorizedUsers"`
	ActiveInstalls  int    `json:"activeInstalls"`
	Requests        int64  `json:"requests"`
	RateLimited     int64  `json:"rateLimited"`
}

// usageReport holds numbers only: how many users and installs, never which.
type usageReport struct {
	Totals usageTotals  `json:"totals"`
	Series []usagePoint `json:"series"`
}

func (h *Handler) getUsage(w http.ResponseWriter, r *http.Request) {
	a, ok := h.appOf(w, r)
	if !ok {
		return
	}
	if !ownership.Allows(a.grants, ownership.UsageView, a.app.ID) {
		respond.MissingPermission(w, ownership.UsageView)
		return
	}
	days, ok := usageDays(w, r)
	if !ok {
		return
	}
	snapshot, err := h.store.AppUsageSnapshot(r.Context(), a.app.ID)
	if err != nil {
		respond.StoreError(w, "appUsageSnapshot", err)
		return
	}
	counts, err := h.requestCounts(r, a.app.ID, days)
	if err != nil {
		respond.StoreError(w, "requestCounts", err)
		return
	}
	respond.JSON(w, http.StatusOK, buildUsage(time.Now(), snapshot, counts))
}

func usageDays(w http.ResponseWriter, r *http.Request) (int, bool) {
	text := r.URL.Query().Get("days")
	if text == "" {
		return defaultUsageDays, true
	}
	days, err := strconv.Atoi(text)
	if err != nil || days < 1 || days > maxUsageDays {
		writeFieldError(w, "usageDays", invalidField("days", "days must be between 1 and "+strconv.Itoa(maxUsageDays)))
		return 0, false
	}
	return days, true
}

func (h *Handler) requestCounts(r *http.Request, clientID string, days int) ([]ratelimit.DayCount, error) {
	if h.usage == nil {
		return emptyCounts(time.Now(), days), nil
	}
	return h.usage.Daily(r.Context(), clientID, days)
}

func emptyCounts(now time.Time, days int) []ratelimit.DayCount {
	counts := make([]ratelimit.DayCount, 0, days)
	for offset := days - 1; offset >= 0; offset-- {
		counts = append(counts, ratelimit.DayCount{Date: now.UTC().AddDate(0, 0, -offset).Format("2006-01-02")})
	}
	return counts
}

// buildUsage turns the facts about an app into the report: one point per day of
// counts, and totals over them.
func buildUsage(now time.Time, snapshot *database.UsageSnapshot, counts []ratelimit.DayCount) usageReport {
	report := usageReport{Series: make([]usagePoint, 0, len(counts))}
	for _, day := range counts {
		report.Series = append(report.Series, pointFor(day, snapshot))
		report.Totals.Requests += day.Requests
		report.Totals.RateLimited += day.RateLimited
	}
	report.Totals.AuthorizedUsers = len(snapshot.AuthorizedAt)
	report.Totals.ActiveInstalls = activeInstallsAt(snapshot.Installs, now)
	report.Totals.StorageBytes = snapshot.StorageBytes
	return report
}

func pointFor(day ratelimit.DayCount, snapshot *database.UsageSnapshot) usagePoint {
	date, err := time.Parse("2006-01-02", day.Date)
	if err != nil {
		return usagePoint{Date: day.Date, Requests: day.Requests, RateLimited: day.RateLimited}
	}
	endOfDay := date.AddDate(0, 0, 1)
	return usagePoint{
		Date: day.Date, AuthorizedUsers: authorizedBy(snapshot.AuthorizedAt, endOfDay),
		ActiveInstalls: activeInstallsAt(snapshot.Installs, endOfDay), Requests: day.Requests, RateLimited: day.RateLimited,
	}
}

func authorizedBy(authorizedAt []time.Time, moment time.Time) int {
	count := 0
	for _, authorized := range authorizedAt {
		if authorized.Before(moment) {
			count++
		}
	}
	return count
}

func activeInstallsAt(installs []database.InstallSpan, moment time.Time) int {
	count := 0
	for _, install := range installs {
		if install.CreatedAt.Before(moment) && (install.RevokedAt == nil || install.RevokedAt.After(moment)) {
			count++
		}
	}
	return count
}
