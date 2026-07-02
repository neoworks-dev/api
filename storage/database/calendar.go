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

type CalendarStore struct {
	DB *surrealdb.DB
}

type dbCalendar struct {
	ID        *models.RecordID `json:"id,omitempty"`
	Name      string           `json:"name"`
	Color     string           `json:"color"`
	IsDefault bool             `json:"is_default"`
	CreatedAt time.Time        `json:"created_at"`
	UpdatedAt time.Time        `json:"updated_at"`
}

type CreateCalendarParams struct {
	Owner     models.RecordID
	Name      string
	Color     string
	IsDefault bool
}

type UpdateCalendarParams struct {
	ID        models.RecordID
	UserID    models.RecordID
	Name      *string
	Color     *string
	IsDefault *bool
}

func calendarToGQL(c *dbCalendar) *gql_model.Calendar {
	id := ""
	if c.ID != nil {
		id = fmt.Sprintf("%v", c.ID.ID)
	}
	return &gql_model.Calendar{
		ID:        id,
		Name:      c.Name,
		Color:     c.Color,
		IsDefault: c.IsDefault,
		CreatedAt: c.CreatedAt.Format(time.RFC3339),
		UpdatedAt: c.UpdatedAt.Format(time.RFC3339),
	}
}

func firstCalendar(results *[]surrealdb.QueryResult[[]dbCalendar]) *gql_model.Calendar {
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return calendarToGQL(&qr.Result[0])
		}
	}
	return nil
}

func (store *CalendarStore) Create(ctx context.Context, params *CreateCalendarParams) (*gql_model.Calendar, error) {
	results, err := surrealdb.Query[[]dbCalendar](ctx, store.DB,
		"CREATE calendar SET owner = $owner, name = $name, color = $color, is_default = $is_default RETURN AFTER",
		map[string]any{"owner": params.Owner, "name": params.Name, "color": params.Color, "is_default": params.IsDefault},
	)
	if err != nil {
		return nil, fmt.Errorf("create calendar: %w", err)
	}
	if c := firstCalendar(results); c != nil {
		return c, nil
	}
	return nil, fmt.Errorf("create calendar: no result returned")
}

// Update is scoped to calendars owned by the caller.
func (store *CalendarStore) Update(ctx context.Context, params *UpdateCalendarParams) (*gql_model.Calendar, error) {
	assignments := []string{}
	queryParams := map[string]any{"id": params.ID, "user": params.UserID}
	if params.Name != nil {
		assignments = append(assignments, "name = $name")
		queryParams["name"] = *params.Name
	}
	if params.Color != nil {
		assignments = append(assignments, "color = $color")
		queryParams["color"] = *params.Color
	}
	if params.IsDefault != nil {
		assignments = append(assignments, "is_default = $is_default")
		queryParams["is_default"] = *params.IsDefault
	}
	if len(assignments) == 0 {
		return store.Get(ctx, params.ID, params.UserID)
	}

	query := fmt.Sprintf(
		"UPDATE $id SET %s WHERE owner = $user RETURN AFTER",
		strings.Join(assignments, ", "),
	)
	results, err := surrealdb.Query[[]dbCalendar](ctx, store.DB, query, queryParams)
	if err != nil {
		return nil, fmt.Errorf("update calendar: %w", err)
	}
	if c := firstCalendar(results); c != nil {
		return c, nil
	}
	return nil, ErrNotFound
}

func (store *CalendarStore) Get(ctx context.Context, id, userID models.RecordID) (*gql_model.Calendar, error) {
	results, err := surrealdb.Query[[]dbCalendar](ctx, store.DB,
		"SELECT * FROM calendar WHERE id = $id AND owner = $user LIMIT 1",
		map[string]any{"id": id, "user": userID},
	)
	if err != nil {
		return nil, fmt.Errorf("get calendar: %w", err)
	}
	if c := firstCalendar(results); c != nil {
		return c, nil
	}
	return nil, ErrNotFound
}

func (store *CalendarStore) Delete(ctx context.Context, id, userID models.RecordID) error {
	_, err := surrealdb.Query[[]any](ctx, store.DB,
		"DELETE calendar WHERE id = $id AND owner = $user",
		map[string]any{"id": id, "user": userID},
	)
	return err
}

// ListForUser returns every calendar owned by the caller.
func (store *CalendarStore) ListForUser(ctx context.Context, userID models.RecordID) ([]*gql_model.Calendar, error) {
	results, err := surrealdb.Query[[]dbCalendar](ctx, store.DB,
		"SELECT * FROM calendar WHERE owner = $user ORDER BY name ASC",
		map[string]any{"user": userID},
	)
	if err != nil {
		return nil, fmt.Errorf("list calendars: %w", err)
	}
	for _, qr := range *results {
		out := make([]*gql_model.Calendar, len(qr.Result))
		for i := range qr.Result {
			out[i] = calendarToGQL(&qr.Result[i])
		}
		return out, nil
	}
	return nil, nil
}
