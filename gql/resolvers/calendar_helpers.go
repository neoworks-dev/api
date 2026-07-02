package gql

import (
	"context"
	"crypto/rand"
	"fmt"

	gql_model "github.com/neoworks/auth/gql/model"
	"github.com/neoworks/auth/storage/database"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// syncEventInvites reconciles attendance edges with the event's participant list
// and notifies the newly-invited users. Best-effort: a failure here never fails
// the surrounding create/update mutation.
func (r *mutationResolver) syncEventInvites(ctx context.Context, event *gql_model.Event, ownerID string, participants map[string]any) {
	eventRef := models.NewRecordID("event", event.ID)
	ownerRef := models.NewRecordID("user", ownerID)
	userIDs := participantUserIDs(participants)
	// Each invitee's policy toward the owner: block drops the invite, auto_accept
	// shares the event immediately. Best-effort — default to no policy on error.
	policies, err := r.store.Connections.InvitePoliciesToward(ctx, ownerRef, userIDs)
	if err != nil {
		policies = nil
	}
	added, err := r.store.Events.SyncAttendance(ctx, eventRef, ownerRef, userIDs, policies)
	if err != nil {
		return
	}
	url := "/?event=" + event.ID
	for _, userID := range added {
		_, _ = r.notify(ctx, userID, "Calendar invitation", "You were invited to \""+event.Title+"\"", &url)
	}
}

// calendarRecord turns an optional calendar id into an optional record link.
// "" clears the link (nil leaves it unchanged on update).
func calendarRecord(id *string) *models.RecordID {
	if id == nil || *id == "" {
		return nil
	}
	ref := models.NewRecordID("calendar", *id)
	return &ref
}

// participantUserIDs pulls the neoworks user ids out of a jsCalendar participants
// map. Each entry is an object that may carry a "userId" (set by the client for
// participants who are neoworks users); email-only invitees have none and are
// skipped — they are not shared via attendance.
func participantUserIDs(participants map[string]any) []string {
	var ids []string
	for _, raw := range participants {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		userID, ok := entry["userId"].(string)
		if !ok || userID == "" {
			continue
		}
		ids = append(ids, userID)
	}
	return ids
}

// newUID returns a random RFC 4122 v4 UUID string for a jsCalendar `uid`.
func newUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func ndaysToData(in []*gql_model.NDayInput) []database.NDayData {
	if in == nil {
		return nil
	}
	out := make([]database.NDayData, 0, len(in))
	for _, n := range in {
		if n == nil {
			continue
		}
		out = append(out, database.NDayData{Day: n.Day, NthOfPeriod: n.NthOfPeriod})
	}
	return out
}

func recurrenceRulesParams(in []*gql_model.RecurrenceRuleInput) []database.RecurrenceRuleData {
	if in == nil {
		return nil
	}
	out := make([]database.RecurrenceRuleData, 0, len(in))
	for _, r := range in {
		if r == nil {
			continue
		}
		out = append(out, database.RecurrenceRuleData{
			Frequency:      r.Frequency,
			Interval:       r.Interval,
			Until:          r.Until,
			Count:          r.Count,
			FirstDayOfWeek: r.FirstDayOfWeek,
			ByDay:          ndaysToData(r.ByDay),
			ByMonthDay:     r.ByMonthDay,
			ByMonth:        r.ByMonth,
			BySetPosition:  r.BySetPosition,
		})
	}
	return out
}

func eventFieldsFromCreate(input gql_model.CreateEventInput) database.EventFields {
	return database.EventFields{
		CalendarID:              calendarRecord(input.CalendarID),
		Title:                   &input.Title,
		Description:             input.Description,
		Start:                   &input.Start,
		Duration:                input.Duration,
		TimeZone:                input.TimeZone,
		ShowWithoutTime:         input.ShowWithoutTime,
		Status:                  input.Status,
		FreeBusyStatus:          input.FreeBusyStatus,
		Privacy:                 input.Privacy,
		Priority:                input.Priority,
		Color:                   input.Color,
		Keywords:                input.Keywords,
		Participants:            input.Participants,
		Locations:               input.Locations,
		VirtualLocations:        input.VirtualLocations,
		Alerts:                  input.Alerts,
		Links:                   input.Links,
		RelatedTo:               input.RelatedTo,
		Localizations:           input.Localizations,
		RecurrenceOverrides:     input.RecurrenceOverrides,
		RecurrenceRules:         recurrenceRulesParams(input.RecurrenceRules),
		ExcludedRecurrenceRules: recurrenceRulesParams(input.ExcludedRecurrenceRules),
	}
}

func eventFieldsFromUpdate(input gql_model.UpdateEventInput) database.EventFields {
	return database.EventFields{
		CalendarID:              calendarRecord(input.CalendarID),
		Title:                   input.Title,
		Description:             input.Description,
		Start:                   input.Start,
		Duration:                input.Duration,
		TimeZone:                input.TimeZone,
		ShowWithoutTime:         input.ShowWithoutTime,
		Status:                  input.Status,
		FreeBusyStatus:          input.FreeBusyStatus,
		Privacy:                 input.Privacy,
		Priority:                input.Priority,
		Color:                   input.Color,
		Keywords:                input.Keywords,
		Participants:            input.Participants,
		Locations:               input.Locations,
		VirtualLocations:        input.VirtualLocations,
		Alerts:                  input.Alerts,
		Links:                   input.Links,
		RelatedTo:               input.RelatedTo,
		Localizations:           input.Localizations,
		RecurrenceOverrides:     input.RecurrenceOverrides,
		RecurrenceRules:         recurrenceRulesParams(input.RecurrenceRules),
		ExcludedRecurrenceRules: recurrenceRulesParams(input.ExcludedRecurrenceRules),
	}
}
