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

type MemoryStore struct {
	DB *surrealdb.DB
}

type dbMemory struct {
	ID           *models.RecordID `json:"id,omitempty"`
	User         *models.RecordID `json:"user,omitempty"`
	Organization *models.RecordID `json:"organization,omitempty"`
	Kind         string           `json:"kind"`
	Title        *string          `json:"title,omitempty"`
	SourceText   *string          `json:"source_text,omitempty"`
	Media        *models.RecordID `json:"media,omitempty"`
	Searchable   bool             `json:"searchable"`
	Deleted      bool             `json:"deleted"`
	CreatedAt    time.Time        `json:"created_at"`
	UpdatedAt    time.Time        `json:"updated_at"`
}

// MemoryFields carries the writable fields shared by create and update. A nil
// pointer means "absent" — omitted from the SET clause so it defaults to NONE.
type MemoryFields struct {
	Kind       *string
	Title      *string
	SourceText *string
	Media      *models.RecordID
	Searchable *bool
}

type CreateMemoryParams struct {
	UserID models.RecordID
	OrgID  *models.RecordID
	Fields MemoryFields
}

type UpdateMemoryParams struct {
	ID     models.RecordID
	UserID models.RecordID
	Fields MemoryFields
}

func recordIDPtr(rid *models.RecordID) *string {
	if rid == nil {
		return nil
	}
	s := fmt.Sprintf("%v", rid.ID)
	return &s
}

func memoryToGQL(m *dbMemory) *gql_model.Memory {
	id := ""
	if m.ID != nil {
		id = fmt.Sprintf("%v", m.ID.ID)
	}
	return &gql_model.Memory{
		ID:             id,
		OrganizationID: recordIDPtr(m.Organization),
		Kind:           m.Kind,
		Title:          m.Title,
		SourceText:     m.SourceText,
		Media:          recordIDPtr(m.Media),
		Searchable:     m.Searchable,
		Deleted:        m.Deleted,
		CreatedAt:      m.CreatedAt.Format(time.RFC3339),
		UpdatedAt:      m.UpdatedAt.Format(time.RFC3339),
	}
}

func firstMemory(results *[]surrealdb.QueryResult[[]dbMemory]) *gql_model.Memory {
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return memoryToGQL(&qr.Result[0])
		}
	}
	return nil
}

// memoryAssignments appends SET clauses + params for each present field.
func memoryAssignments(f *MemoryFields, assignments *[]string, params map[string]any) {
	set := func(clause, key string, value any) {
		*assignments = append(*assignments, clause)
		params[key] = value
	}
	if f.Kind != nil {
		set("kind = $kind", "kind", *f.Kind)
	}
	if f.Title != nil {
		set("title = $title", "title", *f.Title)
	}
	if f.SourceText != nil {
		set("source_text = $source_text", "source_text", *f.SourceText)
	}
	if f.Media != nil {
		set("media = $media", "media", *f.Media)
	}
	if f.Searchable != nil {
		set("searchable = $searchable", "searchable", *f.Searchable)
	}
}

func (store *MemoryStore) Create(ctx context.Context, params *CreateMemoryParams) (*gql_model.Memory, error) {
	assignments := []string{"user = $user"}
	queryParams := map[string]any{"user": params.UserID}
	if params.OrgID != nil {
		assignments = append(assignments, "organization = $organization")
		queryParams["organization"] = *params.OrgID
	}
	memoryAssignments(&params.Fields, &assignments, queryParams)

	query := "CREATE memory SET " + strings.Join(assignments, ", ") + " RETURN AFTER"
	results, err := surrealdb.Query[[]dbMemory](ctx, store.DB, query, queryParams)
	if err != nil {
		return nil, fmt.Errorf("create memory: %w", err)
	}
	if m := firstMemory(results); m != nil {
		return m, nil
	}
	return nil, fmt.Errorf("create memory: no result returned")
}

func (store *MemoryStore) getRaw(ctx context.Context, id, userID models.RecordID) (*dbMemory, error) {
	results, err := surrealdb.Query[[]dbMemory](ctx, store.DB,
		"SELECT * FROM memory WHERE id = $id AND user = $user LIMIT 1",
		map[string]any{"id": id, "user": userID},
	)
	if err != nil {
		return nil, fmt.Errorf("get memory: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return &qr.Result[0], nil
		}
	}
	return nil, ErrNotFound
}

func (store *MemoryStore) Get(ctx context.Context, id, userID models.RecordID) (*gql_model.Memory, error) {
	raw, err := store.getRaw(ctx, id, userID)
	if err != nil {
		return nil, err
	}
	return memoryToGQL(raw), nil
}

func (store *MemoryStore) Update(ctx context.Context, params *UpdateMemoryParams) (*gql_model.Memory, error) {
	assignments := []string{}
	queryParams := map[string]any{"id": params.ID, "user": params.UserID}
	memoryAssignments(&params.Fields, &assignments, queryParams)
	if len(assignments) == 0 {
		return store.Get(ctx, params.ID, params.UserID)
	}

	query := "UPDATE $id SET " + strings.Join(assignments, ", ") + " WHERE user = $user RETURN AFTER"
	results, err := surrealdb.Query[[]dbMemory](ctx, store.DB, query, queryParams)
	if err != nil {
		return nil, fmt.Errorf("update memory: %w", err)
	}
	if m := firstMemory(results); m != nil {
		return m, nil
	}
	return nil, ErrNotFound
}

// Delete soft-deletes the memory and hard-deletes its chunks (vectors must not
// linger for a removed memory).
func (store *MemoryStore) Delete(ctx context.Context, id, userID models.RecordID) error {
	_, err := surrealdb.Query[[]any](ctx, store.DB, `
        UPDATE $id SET deleted = true WHERE user = $user;
        DELETE memory_chunk WHERE memory = $id AND user = $user;
    `, map[string]any{"id": id, "user": userID})
	if err != nil {
		return fmt.Errorf("delete memory: %w", err)
	}
	return nil
}

// ClearSearchable turns indexing off: it clears the plaintext source and drops
// every chunk/vector in one statement batch, so no searchable trace of private
// content remains once the call returns.
func (store *MemoryStore) ClearSearchable(ctx context.Context, id, userID models.RecordID) (*gql_model.Memory, error) {
	results, err := surrealdb.Query[[]dbMemory](ctx, store.DB, `
        UPDATE $id SET searchable = false, source_text = NONE WHERE user = $user RETURN AFTER;
        DELETE memory_chunk WHERE memory = $id AND user = $user;
    `, map[string]any{"id": id, "user": userID})
	if err != nil {
		return nil, fmt.Errorf("clear searchable: %w", err)
	}
	if m := firstMemory(results); m != nil {
		return m, nil
	}
	return nil, ErrNotFound
}

// List returns the caller's memories (soft-deleted excluded unless the filter
// explicitly asks for them).
func (store *MemoryStore) List(ctx context.Context, userID models.RecordID, filter *gql_model.MemoryFilter, sort []*gql_model.MemorySort, limit, offset int) ([]*gql_model.Memory, error) {
	conditions, queryParams, err := store.listConditions(userID, filter)
	if err != nil {
		return nil, err
	}
	query := "SELECT * FROM memory WHERE " + strings.Join(conditions, " AND ") +
		memoryOrderBy(sort) + fmt.Sprintf(" LIMIT %d START %d", limit, offset)
	results, err := surrealdb.Query[[]dbMemory](ctx, store.DB, query, queryParams)
	if err != nil {
		return nil, fmt.Errorf("list memories: %w", err)
	}
	for _, qr := range *results {
		out := make([]*gql_model.Memory, len(qr.Result))
		for i := range qr.Result {
			out[i] = memoryToGQL(&qr.Result[i])
		}
		return out, nil
	}
	return nil, nil
}

func (store *MemoryStore) Count(ctx context.Context, userID models.RecordID, filter *gql_model.MemoryFilter) (int, error) {
	conditions, queryParams, err := store.listConditions(userID, filter)
	if err != nil {
		return 0, err
	}
	query := "SELECT count() FROM memory WHERE " + strings.Join(conditions, " AND ") + " GROUP ALL"
	results, err := surrealdb.Query[[]struct {
		Count int `json:"count"`
	}](ctx, store.DB, query, queryParams)
	if err != nil {
		return 0, fmt.Errorf("count memories: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return qr.Result[0].Count, nil
		}
	}
	return 0, nil
}

// listConditions builds the shared WHERE for List/Count: always user-scoped, and
// soft-deleted excluded unless the caller filters on `deleted` explicitly.
func (store *MemoryStore) listConditions(userID models.RecordID, filter *gql_model.MemoryFilter) ([]string, map[string]any, error) {
	conditions := []string{"user = $user"}
	queryParams := map[string]any{"user": userID}
	if filter == nil || filter.Deleted == nil {
		conditions = append(conditions, "deleted = false")
	}
	if filter != nil {
		compiler := newFilterCompiler()
		expr := memoryFilterEngine.compile(compiler, filter)
		if compiler.err != nil {
			return nil, nil, compiler.err
		}
		if expr != "" {
			conditions = append(conditions, expr)
			for name, value := range compiler.params {
				queryParams[name] = value
			}
		}
	}
	return conditions, queryParams, nil
}

func memoryOrderBy(sort []*gql_model.MemorySort) string {
	columns := map[gql_model.MemorySortField]string{
		gql_model.MemorySortFieldCreatedAt: "created_at",
		gql_model.MemorySortFieldUpdatedAt: "updated_at",
		gql_model.MemorySortFieldTitle:     "title",
	}
	if len(sort) == 0 {
		return " ORDER BY created_at DESC"
	}
	var keys []string
	for _, s := range sort {
		col, ok := columns[s.Field]
		if !ok {
			continue
		}
		direction := "DESC"
		if s.Direction != nil && *s.Direction == gql_model.SortDirectionAsc {
			direction = "ASC"
		}
		keys = append(keys, col+" "+direction)
	}
	if len(keys) == 0 {
		return " ORDER BY created_at DESC"
	}
	return " ORDER BY " + strings.Join(keys, ", ")
}
