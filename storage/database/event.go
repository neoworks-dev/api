package database

import (
	"context"
	"fmt"
	"strings"
	"time"

	gql_model "github.com/neoworks/auth/gql/model"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

type EventStore struct {
	DB *surrealdb.DB
}

// NDayData is a jsCalendar NDay: a weekday optionally restricted to the Nth
// occurrence within the period.
type NDayData struct {
	Day         string `json:"day"`
	NthOfPeriod *int   `json:"nthOfPeriod,omitempty"`
}

// RecurrenceRuleData is a jsCalendar RecurrenceRule (subset).
type RecurrenceRuleData struct {
	Frequency      string     `json:"frequency"`
	Interval       *int       `json:"interval,omitempty"`
	Until          *string    `json:"until,omitempty"`
	Count          *int       `json:"count,omitempty"`
	FirstDayOfWeek *string    `json:"firstDayOfWeek,omitempty"`
	ByDay          []NDayData `json:"byDay,omitempty"`
	ByMonthDay     []int      `json:"byMonthDay,omitempty"`
	ByMonth        []string   `json:"byMonth,omitempty"`
	BySetPosition  []int      `json:"bySetPosition,omitempty"`
}

type dbEvent struct {
	ID       *models.RecordID `json:"id,omitempty"`
	Owner    *models.RecordID `json:"owner,omitempty"`
	Calendar *models.RecordID `json:"calendar,omitempty"`

	// MyAttendance is derived per caller (not a stored column): "owner" for the
	// owner, else the caller's attendance status, else nil. Set before eventToGQL.
	MyAttendance *string `json:"-"`

	UID         string  `json:"uid"`
	Title       string  `json:"title"`
	Description *string `json:"description,omitempty"`

	Start           string  `json:"start"`
	Duration        *string `json:"duration,omitempty"`
	TimeZone        *string `json:"time_zone,omitempty"`
	ShowWithoutTime bool    `json:"show_without_time"`

	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`

	Status         *string  `json:"status,omitempty"`
	FreeBusyStatus *string  `json:"free_busy_status,omitempty"`
	Privacy        *string  `json:"privacy,omitempty"`
	Priority       *int     `json:"priority,omitempty"`
	Color          *string  `json:"color,omitempty"`
	Sequence       *int     `json:"sequence,omitempty"`
	Keywords       []string `json:"keywords,omitempty"`

	Participants            map[string]any       `json:"participants,omitempty"`
	Locations               map[string]any       `json:"locations,omitempty"`
	VirtualLocations        map[string]any       `json:"virtual_locations,omitempty"`
	Alerts                  map[string]any       `json:"alerts,omitempty"`
	Links                   map[string]any       `json:"links,omitempty"`
	RelatedTo               map[string]any       `json:"related_to,omitempty"`
	Localizations           map[string]any       `json:"localizations,omitempty"`
	RecurrenceOverrides     map[string]any       `json:"recurrence_overrides,omitempty"`
	RecurrenceRules         []RecurrenceRuleData `json:"recurrence_rules,omitempty"`
	ExcludedRecurrenceRules []RecurrenceRuleData `json:"excluded_recurrence_rules,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// EventFields carries the writable jsCalendar fields shared by create and update.
// Pointer/slice/map nil means "absent" — omitted from the SET clause.
type EventFields struct {
	CalendarID      *models.RecordID
	Title           *string
	Description     *string
	Start           *string
	Duration        *string
	TimeZone        *string
	ShowWithoutTime *bool
	Status          *string
	FreeBusyStatus  *string
	Privacy         *string
	Priority        *int
	Color           *string
	Keywords        []string
	Participants            map[string]any
	Locations               map[string]any
	VirtualLocations        map[string]any
	Alerts                  map[string]any
	Links                   map[string]any
	RelatedTo               map[string]any
	Localizations           map[string]any
	RecurrenceOverrides     map[string]any
	RecurrenceRules         []RecurrenceRuleData
	ExcludedRecurrenceRules []RecurrenceRuleData
}

type CreateEventParams struct {
	Owner  models.RecordID
	UID    string
	Fields EventFields
}

type UpdateEventParams struct {
	ID     models.RecordID
	UserID models.RecordID
	Fields EventFields
}

func ndaysToGQL(in []NDayData) []*gql_model.NDay {
	if in == nil {
		return nil
	}
	out := make([]*gql_model.NDay, len(in))
	for i := range in {
		out[i] = &gql_model.NDay{Day: in[i].Day, NthOfPeriod: in[i].NthOfPeriod}
	}
	return out
}

func recurrenceRulesToGQL(in []RecurrenceRuleData) []*gql_model.RecurrenceRule {
	if in == nil {
		return nil
	}
	out := make([]*gql_model.RecurrenceRule, len(in))
	for i := range in {
		out[i] = &gql_model.RecurrenceRule{
			Frequency:      in[i].Frequency,
			Interval:       in[i].Interval,
			Until:          in[i].Until,
			Count:          in[i].Count,
			FirstDayOfWeek: in[i].FirstDayOfWeek,
			ByDay:          ndaysToGQL(in[i].ByDay),
			ByMonthDay:     in[i].ByMonthDay,
			ByMonth:        in[i].ByMonth,
			BySetPosition:  in[i].BySetPosition,
		}
	}
	return out
}

func eventToGQL(e *dbEvent) *gql_model.Event {
	id := ""
	if e.ID != nil {
		id = fmt.Sprintf("%v", e.ID.ID)
	}
	var calendarID *string
	if e.Calendar != nil {
		cid := fmt.Sprintf("%v", e.Calendar.ID)
		calendarID = &cid
	}
	ownerID := ""
	if e.Owner != nil {
		ownerID = fmt.Sprintf("%v", e.Owner.ID)
	}
	return &gql_model.Event{
		ID:                      id,
		OwnerID:                 ownerID,
		MyAttendance:            e.MyAttendance,
		UID:                     e.UID,
		CalendarID:              calendarID,
		Title:                   e.Title,
		Description:             e.Description,
		Start:                   e.Start,
		Duration:                e.Duration,
		TimeZone:                e.TimeZone,
		ShowWithoutTime:         e.ShowWithoutTime,
		Status:                  e.Status,
		FreeBusyStatus:          e.FreeBusyStatus,
		Privacy:                 e.Privacy,
		Priority:                e.Priority,
		Color:                   e.Color,
		Sequence:                e.Sequence,
		Keywords:                e.Keywords,
		Participants:            e.Participants,
		Locations:               e.Locations,
		VirtualLocations:        e.VirtualLocations,
		Alerts:                  e.Alerts,
		Links:                   e.Links,
		RelatedTo:               e.RelatedTo,
		Localizations:           e.Localizations,
		RecurrenceOverrides:     e.RecurrenceOverrides,
		RecurrenceRules:         recurrenceRulesToGQL(e.RecurrenceRules),
		ExcludedRecurrenceRules: recurrenceRulesToGQL(e.ExcludedRecurrenceRules),
		CreatedAt:               e.CreatedAt.Format(time.RFC3339),
		UpdatedAt:               e.UpdatedAt.Format(time.RFC3339),
	}
}

func firstRawEvent(results *[]surrealdb.QueryResult[[]dbEvent]) *dbEvent {
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return &qr.Result[0]
		}
	}
	return nil
}

// Access scopes shared by the event queries. An event is readable by its owner or
// by anyone holding an accepted/pending invite (pending so they can respond to it);
// it is editable by the owner or an accepted attendee only.
const (
	eventReadScope = `(owner = $user OR id IN (SELECT VALUE out FROM attendance WHERE in = $user AND status IN ["accepted", "pending"]))`
	eventEditScope = `(owner = $user OR id IN (SELECT VALUE out FROM attendance WHERE in = $user AND status = "accepted"))`
)

func sameRecord(a *models.RecordID, b models.RecordID) bool {
	return a != nil && a.Table == b.Table && fmt.Sprintf("%v", a.ID) == fmt.Sprintf("%v", b.ID)
}

// setMyAttendance derives the caller's relationship to an event. The owner is
// "owner"; otherwise the caller's attendance status (if any) from statusByEvent,
// keyed by the event's id string.
func setMyAttendance(e *dbEvent, userID models.RecordID, statusByEvent map[string]string) {
	if sameRecord(e.Owner, userID) {
		owner := "owner"
		e.MyAttendance = &owner
		return
	}
	if e.ID == nil {
		return
	}
	if status, ok := statusByEvent[fmt.Sprintf("%v", e.ID.ID)]; ok {
		e.MyAttendance = &status
	}
}

// attendanceStatus returns the caller's invite status for a single event, or nil.
func (store *EventStore) attendanceStatus(ctx context.Context, userID, eventID models.RecordID) (*string, error) {
	results, err := surrealdb.Query[[]string](ctx, store.DB,
		`SELECT VALUE status FROM attendance WHERE in = $user AND out = $event LIMIT 1`,
		map[string]any{"user": userID, "event": eventID},
	)
	if err != nil {
		return nil, fmt.Errorf("attendance status: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			status := qr.Result[0]
			return &status, nil
		}
	}
	return nil, nil
}

// resolvedEvent fills MyAttendance for a single fetched event (one extra query
// unless the caller owns it) and converts to the GraphQL model.
func (store *EventStore) resolvedEvent(ctx context.Context, e *dbEvent, userID models.RecordID) (*gql_model.Event, error) {
	if sameRecord(e.Owner, userID) {
		owner := "owner"
		e.MyAttendance = &owner
	} else if e.ID != nil {
		status, err := store.attendanceStatus(ctx, userID, *e.ID)
		if err != nil {
			return nil, err
		}
		e.MyAttendance = status
	}
	return eventToGQL(e), nil
}

// fieldAssignments appends SET clauses + params for each present field. `start`
// drives the derived absolute bounds, which are always recomputed when timing
// fields are present.
func fieldAssignments(f *EventFields, assignments *[]string, params map[string]any, knownStart string, knownDuration, knownTZ *string) error {
	set := func(clause, key string, value any) {
		*assignments = append(*assignments, clause)
		params[key] = value
	}
	if f.CalendarID != nil {
		set("calendar = $calendar", "calendar", *f.CalendarID)
	}
	if f.Title != nil {
		set("title = $title", "title", *f.Title)
	}
	if f.Description != nil {
		set("description = $description", "description", *f.Description)
	}
	if f.Start != nil {
		set("start = $start", "start", *f.Start)
	}
	if f.Duration != nil {
		set("duration = $duration", "duration", *f.Duration)
	}
	if f.TimeZone != nil {
		set("time_zone = $time_zone", "time_zone", *f.TimeZone)
	}
	if f.ShowWithoutTime != nil {
		set("show_without_time = $show_without_time", "show_without_time", *f.ShowWithoutTime)
	}
	if f.Status != nil {
		set("status = $status", "status", *f.Status)
	}
	if f.FreeBusyStatus != nil {
		set("free_busy_status = $free_busy_status", "free_busy_status", *f.FreeBusyStatus)
	}
	if f.Privacy != nil {
		set("privacy = $privacy", "privacy", *f.Privacy)
	}
	if f.Priority != nil {
		set("priority = $priority", "priority", *f.Priority)
	}
	if f.Color != nil {
		set("color = $color", "color", *f.Color)
	}
	if f.Keywords != nil {
		set("keywords = $keywords", "keywords", f.Keywords)
	}
	if f.Participants != nil {
		set("participants = $participants", "participants", f.Participants)
	}
	if f.Locations != nil {
		set("locations = $locations", "locations", f.Locations)
	}
	if f.VirtualLocations != nil {
		set("virtual_locations = $virtual_locations", "virtual_locations", f.VirtualLocations)
	}
	if f.Alerts != nil {
		set("alerts = $alerts", "alerts", f.Alerts)
	}
	if f.Links != nil {
		set("links = $links", "links", f.Links)
	}
	if f.RelatedTo != nil {
		set("related_to = $related_to", "related_to", f.RelatedTo)
	}
	if f.Localizations != nil {
		set("localizations = $localizations", "localizations", f.Localizations)
	}
	if f.RecurrenceOverrides != nil {
		set("recurrence_overrides = $recurrence_overrides", "recurrence_overrides", f.RecurrenceOverrides)
	}
	// A non-nil but empty slice means "clear it"; unset to NONE rather than
	// storing an empty array (which would read back as a recurring master).
	if f.RecurrenceRules != nil {
		if len(f.RecurrenceRules) == 0 {
			*assignments = append(*assignments, "recurrence_rules = NONE")
		} else {
			set("recurrence_rules = $recurrence_rules", "recurrence_rules", f.RecurrenceRules)
		}
	}
	if f.ExcludedRecurrenceRules != nil {
		if len(f.ExcludedRecurrenceRules) == 0 {
			*assignments = append(*assignments, "excluded_recurrence_rules = NONE")
		} else {
			set("excluded_recurrence_rules = $excluded_recurrence_rules", "excluded_recurrence_rules", f.ExcludedRecurrenceRules)
		}
	}

	// Recompute the derived UTC bounds whenever any timing field is present.
	if f.Start != nil || f.Duration != nil || f.TimeZone != nil {
		start := knownStart
		if f.Start != nil {
			start = *f.Start
		}
		duration := knownDuration
		if f.Duration != nil {
			duration = f.Duration
		}
		tz := knownTZ
		if f.TimeZone != nil {
			tz = f.TimeZone
		}
		startUTC, endUTC, err := deriveBounds(start, duration, tz)
		if err != nil {
			return err
		}
		set("start_time = $start_time", "start_time", startUTC)
		set("end_time = $end_time", "end_time", endUTC)
	}
	return nil
}

func (store *EventStore) Create(ctx context.Context, params *CreateEventParams) (*gql_model.Event, error) {
	if params.Fields.Start == nil {
		return nil, fmt.Errorf("create event: start is required")
	}
	assignments := []string{
		"owner = $owner",
		"created_by = $owner",
		"uid = $uid",
	}
	queryParams := map[string]any{
		"owner": params.Owner,
		"uid":   params.UID,
	}
	if err := fieldAssignments(&params.Fields, &assignments, queryParams, "", nil, nil); err != nil {
		return nil, err
	}

	query := "CREATE event SET " + strings.Join(assignments, ", ") + " RETURN AFTER"
	results, err := surrealdb.Query[[]dbEvent](ctx, store.DB, query, queryParams)
	if err != nil {
		return nil, fmt.Errorf("create event: %w", err)
	}
	if e := firstRawEvent(results); e != nil {
		return store.resolvedEvent(ctx, e, params.Owner)
	}
	return nil, fmt.Errorf("create event: no result returned")
}

// Update is scoped to events owned by an org the caller belongs to. Timing fields
// recompute the derived bounds; current values are read first so a partial timing
// update stays consistent.
func (store *EventStore) Update(ctx context.Context, params *UpdateEventParams) (*gql_model.Event, error) {
	current, err := store.getRaw(ctx, params.ID, params.UserID)
	if err != nil {
		return nil, err
	}

	assignments := []string{}
	queryParams := map[string]any{"id": params.ID, "user": params.UserID}
	if err := fieldAssignments(&params.Fields, &assignments, queryParams, current.Start, current.Duration, current.TimeZone); err != nil {
		return nil, err
	}
	if len(assignments) == 0 {
		return store.resolvedEvent(ctx, current, params.UserID)
	}

	query := fmt.Sprintf(
		"UPDATE $id SET %s WHERE %s RETURN AFTER",
		strings.Join(assignments, ", "), eventEditScope,
	)
	results, err := surrealdb.Query[[]dbEvent](ctx, store.DB, query, queryParams)
	if err != nil {
		return nil, fmt.Errorf("update event: %w", err)
	}
	if e := firstRawEvent(results); e != nil {
		return store.resolvedEvent(ctx, e, params.UserID)
	}
	return nil, ErrNotFound
}

func (store *EventStore) getRaw(ctx context.Context, id, userID models.RecordID) (*dbEvent, error) {
	results, err := surrealdb.Query[[]dbEvent](ctx, store.DB,
		"SELECT * FROM event WHERE id = $id AND "+eventReadScope+" LIMIT 1",
		map[string]any{"id": id, "user": userID},
	)
	if err != nil {
		return nil, fmt.Errorf("get event: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return &qr.Result[0], nil
		}
	}
	return nil, ErrNotFound
}

func (store *EventStore) Get(ctx context.Context, id, userID models.RecordID) (*gql_model.Event, error) {
	raw, err := store.getRaw(ctx, id, userID)
	if err != nil {
		return nil, err
	}
	return store.resolvedEvent(ctx, raw, userID)
}

// Delete is owner-only. An invited attendee leaves a shared event by declining
// (RespondToInvite), which never removes the underlying record.
func (store *EventStore) Delete(ctx context.Context, id, userID models.RecordID) error {
	_, err := surrealdb.Query[[]any](ctx, store.DB,
		"DELETE event WHERE id = $id AND owner = $user",
		map[string]any{"id": id, "user": userID},
	)
	return err
}

// ListForUser returns the caller's events (owned + accepted/pending invites)
// overlapping [from, to] (nil bounds = unbounded). Recurring masters are always
// included regardless of the window so the client can expand them.
func (store *EventStore) ListForUser(ctx context.Context, userID models.RecordID, from, to *string, filter *gql_model.EventFilter) ([]*gql_model.Event, error) {
	conditions := []string{eventReadScope}
	queryParams := map[string]any{"user": userID}
	if from != nil {
		conditions = append(conditions, "(recurrence_rules != NONE OR end_time >= <datetime>$from)")
		queryParams["from"] = *from
	}
	if to != nil {
		conditions = append(conditions, "(recurrence_rules != NONE OR start_time <= <datetime>$to)")
		queryParams["to"] = *to
	}
	// Structured field filter compiled to a WHERE expression with bound params,
	// reusing the shared compiler (see event_filter.go).
	if filter != nil {
		compiler := newFilterCompiler()
		expr := eventFilterEngine.compile(compiler, filter)
		if compiler.err != nil {
			return nil, compiler.err
		}
		if expr != "" {
			conditions = append(conditions, expr)
			for name, value := range compiler.params {
				queryParams[name] = value
			}
		}
	}

	query := "SELECT * FROM event WHERE " + strings.Join(conditions, " AND ") + " ORDER BY start_time ASC"
	results, err := surrealdb.Query[[]dbEvent](ctx, store.DB, query, queryParams)
	if err != nil {
		return nil, fmt.Errorf("list events: %w", err)
	}

	// One query for the caller's invite statuses, mapped onto the events below
	// (avoids a per-row attendance lookup).
	statusByEvent, err := store.attendanceStatusesForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	for _, qr := range *results {
		out := make([]*gql_model.Event, len(qr.Result))
		for i := range qr.Result {
			setMyAttendance(&qr.Result[i], userID, statusByEvent)
			out[i] = eventToGQL(&qr.Result[i])
		}
		return out, nil
	}
	return nil, nil
}

// attendanceStatusesForUser maps event id (the bare id, no table prefix) → the
// caller's attendance status, for every event they've been invited to.
func (store *EventStore) attendanceStatusesForUser(ctx context.Context, userID models.RecordID) (map[string]string, error) {
	type edge struct {
		Out    models.RecordID `json:"out"`
		Status string          `json:"status"`
	}
	results, err := surrealdb.Query[[]edge](ctx, store.DB,
		"SELECT out, status FROM attendance WHERE in = $user",
		map[string]any{"user": userID},
	)
	if err != nil {
		return nil, fmt.Errorf("list attendance: %w", err)
	}
	byEvent := map[string]string{}
	for _, qr := range *results {
		for _, e := range qr.Result {
			byEvent[fmt.Sprintf("%v", e.Out.ID)] = e.Status
		}
	}
	return byEvent, nil
}

// SyncAttendance reconciles the attendance edges of an event with the set of
// invited user ids (participants carrying a userId, excluding the owner). New
// invitees get a pending edge — unless `policies[userId]` overrides it: "block"
// drops the invite entirely, "auto_accept" creates an already-accepted edge.
// Users no longer invited have their edge removed. Returns the user ids that were
// newly invited (and not blocked), so the caller can notify them.
func (store *EventStore) SyncAttendance(ctx context.Context, eventID, owner models.RecordID, userIDs []string, policies map[string]string) ([]string, error) {
	wanted := map[string]bool{}
	for _, id := range userIDs {
		if id == "" || id == fmt.Sprintf("%v", owner.ID) {
			continue
		}
		wanted[id] = true
	}

	existing, err := store.attendeesOf(ctx, eventID)
	if err != nil {
		return nil, err
	}

	var added []string
	for id := range wanted {
		if existing[id] {
			continue
		}
		if policies[id] == "block" {
			continue // this invitee has blocked the owner's invites
		}
		status := "pending"
		if policies[id] == "auto_accept" {
			status = "accepted"
		}
		userRef := models.NewRecordID("user", id)
		if _, err := surrealdb.Query[[]any](ctx, store.DB,
			"RELATE $user->attendance->$event SET status = $status",
			map[string]any{"user": userRef, "event": eventID, "status": status},
		); err != nil {
			return nil, fmt.Errorf("invite attendee: %w", err)
		}
		added = append(added, id)
	}
	for id := range existing {
		if wanted[id] {
			continue
		}
		userRef := models.NewRecordID("user", id)
		if _, err := surrealdb.Query[[]any](ctx, store.DB,
			"DELETE attendance WHERE in = $user AND out = $event",
			map[string]any{"user": userRef, "event": eventID},
		); err != nil {
			return nil, fmt.Errorf("remove attendee: %w", err)
		}
	}
	return added, nil
}

// attendeesOf returns the set of invited user ids (bare, no table prefix) for an event.
func (store *EventStore) attendeesOf(ctx context.Context, eventID models.RecordID) (map[string]bool, error) {
	results, err := surrealdb.Query[[]struct {
		In models.RecordID `json:"in"`
	}](ctx, store.DB,
		"SELECT in FROM attendance WHERE out = $event",
		map[string]any{"event": eventID},
	)
	if err != nil {
		return nil, fmt.Errorf("list attendees: %w", err)
	}
	out := map[string]bool{}
	for _, qr := range *results {
		for _, e := range qr.Result {
			out[fmt.Sprintf("%v", e.In.ID)] = true
		}
	}
	return out, nil
}

// RespondToInvite flips the caller's invite to accepted or declined. The event
// must exist and the caller must hold an invite edge; returns the updated event.
func (store *EventStore) RespondToInvite(ctx context.Context, eventID, userID models.RecordID, accept bool) (*gql_model.Event, error) {
	status := "declined"
	if accept {
		status = "accepted"
	}
	results, err := surrealdb.Query[[]any](ctx, store.DB,
		"UPDATE attendance SET status = $status WHERE in = $user AND out = $event",
		map[string]any{"status": status, "user": userID, "event": eventID},
	)
	if err != nil {
		return nil, fmt.Errorf("respond to invite: %w", err)
	}
	updated := false
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			updated = true
		}
	}
	if !updated {
		return nil, ErrNotFound
	}
	// A declined event drops out of the caller's read scope; nothing to return.
	if !accept {
		return nil, nil
	}
	return store.Get(ctx, eventID, userID)
}

// OwnerOf returns the owner user id (bare) of an event, for notifying the owner.
func (store *EventStore) OwnerOf(ctx context.Context, eventID models.RecordID) (string, error) {
	results, err := surrealdb.Query[[]struct {
		Owner models.RecordID `json:"owner"`
	}](ctx, store.DB,
		"SELECT owner FROM event WHERE id = $event LIMIT 1",
		map[string]any{"event": eventID},
	)
	if err != nil {
		return "", fmt.Errorf("owner of: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return fmt.Sprintf("%v", qr.Result[0].Owner.ID), nil
		}
	}
	return "", ErrNotFound
}
