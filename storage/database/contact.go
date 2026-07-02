package database

import (
	"context"
	"fmt"
	"strings"
	"time"

	gql_model "github.com/neoworks/auth/gql/model"
	"github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

type ContactStore struct {
	DB *surrealdb.DB
}

// ── Stored shapes (Surreal-native types; json tags match the DB fields) ────────

type NameData struct {
	Family     *string  `json:"family,omitempty"`
	Given      *string  `json:"given,omitempty"`
	Additional []string `json:"additional,omitempty"`
	Prefixes   []string `json:"prefixes,omitempty"`
	Suffixes   []string `json:"suffixes,omitempty"`
}

type GenderData struct {
	Sex      *string `json:"sex,omitempty"`
	Identity *string `json:"identity,omitempty"`
}

type GeoData struct {
	Lat float64 `json:"lat"`
	Lng float64 `json:"lng"`
}

// FieldData is a typed, repeatable value (EMAIL, TEL, IMPP, URL, LANG).
type FieldData struct {
	Value string   `json:"value"`
	Types []string `json:"types,omitempty"`
	Pref  *int     `json:"pref,omitempty"`
	Label *string  `json:"label,omitempty"`
}

type AddressData struct {
	Types      []string `json:"types,omitempty"`
	Pref       *int     `json:"pref,omitempty"`
	Label      *string  `json:"label,omitempty"`
	PoBox      *string  `json:"po_box,omitempty"`
	Ext        *string  `json:"ext,omitempty"`
	Street     *string  `json:"street,omitempty"`
	Locality   *string  `json:"locality,omitempty"`
	Region     *string  `json:"region,omitempty"`
	PostalCode *string  `json:"postal_code,omitempty"`
	Country    *string  `json:"country,omitempty"`
}

type OrgData struct {
	Name  string   `json:"name"`
	Units []string `json:"units,omitempty"`
}

type CustomFieldData struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

type dbContact struct {
	ID *models.RecordID `json:"id,omitempty"`

	UID           string       `json:"uid"`
	Kind          string       `json:"kind"`
	FormattedName string       `json:"formatted_name"`
	Name          *NameData    `json:"name,omitempty"`
	Nicknames     []string     `json:"nicknames,omitempty"`
	Birthday      *string      `json:"birthday,omitempty"`
	Anniversary   *string      `json:"anniversary,omitempty"`
	Gender        *GenderData  `json:"gender,omitempty"`
	Emails        []FieldData  `json:"emails,omitempty"`
	Phones        []FieldData  `json:"phones,omitempty"`
	Impps         []FieldData  `json:"impps,omitempty"`
	Languages     []FieldData  `json:"languages,omitempty"`
	Addresses     []AddressData `json:"addresses,omitempty"`
	Organizations []OrgData    `json:"organizations,omitempty"`
	Title         *string      `json:"title,omitempty"`
	Role          *string      `json:"role,omitempty"`
	Timezone      *string      `json:"timezone,omitempty"`
	Geo           *GeoData     `json:"geo,omitempty"`
	Categories    []string     `json:"categories,omitempty"`
	Notes         []string     `json:"notes,omitempty"`
	Urls          []FieldData  `json:"urls,omitempty"`
	Source        *string      `json:"source,omitempty"`
	Prodid        *string      `json:"prodid,omitempty"`
	Fburl         *string      `json:"fburl,omitempty"`
	Caluri        *string      `json:"caluri,omitempty"`
	Caladruri     *string      `json:"caladruri,omitempty"`
	Photo         *models.RecordID  `json:"photo,omitempty"`
	Logo          *models.RecordID  `json:"logo,omitempty"`
	Sound         *models.RecordID  `json:"sound,omitempty"`
	Key           *models.RecordID  `json:"key,omitempty"`
	CustomFields  []CustomFieldData `json:"custom_fields,omitempty"`
	Favorite      bool         `json:"favorite"`
	Archived      bool         `json:"archived"`
	Deleted       bool         `json:"deleted"`

	ContactID *models.RecordID  `json:"contact_id,omitempty"` // set on version rows
	ParentIDs []models.RecordID `json:"parent_ids,omitempty"` // lineage parents, on version rows
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

func recordIDStrings(ids []models.RecordID) []string {
	if ids == nil {
		return nil
	}
	out := make([]string, len(ids))
	for i := range ids {
		out[i] = recordIDString(&ids[i])
	}
	return out
}

// ── db → gql conversion ────────────────────────────────────────────────────────

func fieldsToGQL(in []FieldData) []*gql_model.ContactField {
	if in == nil {
		return nil
	}
	out := make([]*gql_model.ContactField, len(in))
	for i, f := range in {
		out[i] = &gql_model.ContactField{Value: f.Value, Types: f.Types, Pref: f.Pref, Label: f.Label}
	}
	return out
}

func nameToGQL(n *NameData) *gql_model.Name {
	if n == nil {
		return nil
	}
	return &gql_model.Name{Family: n.Family, Given: n.Given, Additional: n.Additional, Prefixes: n.Prefixes, Suffixes: n.Suffixes}
}

func genderToGQL(g *GenderData) *gql_model.Gender {
	if g == nil {
		return nil
	}
	return &gql_model.Gender{Sex: g.Sex, Identity: g.Identity}
}

func geoToGQL(g *GeoData) *gql_model.Geo {
	if g == nil {
		return nil
	}
	return &gql_model.Geo{Lat: g.Lat, Lng: g.Lng}
}

func addressesToGQL(in []AddressData) []*gql_model.Address {
	if in == nil {
		return nil
	}
	out := make([]*gql_model.Address, len(in))
	for i, a := range in {
		out[i] = &gql_model.Address{
			Types: a.Types, Pref: a.Pref, Label: a.Label, PoBox: a.PoBox, Ext: a.Ext,
			Street: a.Street, Locality: a.Locality, Region: a.Region, PostalCode: a.PostalCode, Country: a.Country,
		}
	}
	return out
}

func orgsToGQL(in []OrgData) []*gql_model.ContactOrganization {
	if in == nil {
		return nil
	}
	out := make([]*gql_model.ContactOrganization, len(in))
	for i, o := range in {
		out[i] = &gql_model.ContactOrganization{Name: o.Name, Units: o.Units}
	}
	return out
}

func customFieldsToGQL(in []CustomFieldData) []*gql_model.CustomField {
	if in == nil {
		return nil
	}
	out := make([]*gql_model.CustomField, len(in))
	for i, c := range in {
		out[i] = &gql_model.CustomField{Label: c.Label, Value: c.Value}
	}
	return out
}

func mediaID(r *models.RecordID) *string {
	if r == nil {
		return nil
	}
	id := recordIDString(r)
	return &id
}

func (c *dbContact) toGQL() *gql_model.Contact {
	return &gql_model.Contact{
		ID:            recordIDString(c.ID),
		UID:           c.UID,
		Kind:          c.Kind,
		FormattedName: c.FormattedName,
		Name:          nameToGQL(c.Name),
		Nicknames:     c.Nicknames,
		Birthday:      c.Birthday,
		Anniversary:   c.Anniversary,
		Gender:        genderToGQL(c.Gender),
		Emails:        fieldsToGQL(c.Emails),
		Phones:        fieldsToGQL(c.Phones),
		Impps:         fieldsToGQL(c.Impps),
		Languages:     fieldsToGQL(c.Languages),
		Addresses:     addressesToGQL(c.Addresses),
		Organizations: orgsToGQL(c.Organizations),
		Title:         c.Title,
		Role:          c.Role,
		Timezone:      c.Timezone,
		Geo:           geoToGQL(c.Geo),
		Categories:    c.Categories,
		Notes:         c.Notes,
		Urls:          fieldsToGQL(c.Urls),
		Source:        c.Source,
		Prodid:        c.Prodid,
		Fburl:         c.Fburl,
		Caluri:        c.Caluri,
		Caladruri:     c.Caladruri,
		Photo:         mediaID(c.Photo),
		Logo:          mediaID(c.Logo),
		Sound:         mediaID(c.Sound),
		Key:           mediaID(c.Key),
		CustomFields:  customFieldsToGQL(c.CustomFields),
		Favorite:      c.Favorite,
		Archived:      c.Archived,
		Deleted:       c.Deleted,
		CreatedAt:     c.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     c.UpdatedAt.Format(time.RFC3339),
	}
}

func (c *dbContact) toVersionGQL() *gql_model.ContactVersion {
	g := c.toGQL()
	return &gql_model.ContactVersion{
		ID: recordIDString(c.ID), ContactID: recordIDString(c.ContactID),
		UID: g.UID, Kind: g.Kind, FormattedName: g.FormattedName, Name: g.Name, Nicknames: g.Nicknames,
		Birthday: g.Birthday, Anniversary: g.Anniversary, Gender: g.Gender, Emails: g.Emails, Phones: g.Phones,
		Impps: g.Impps, Languages: g.Languages, Addresses: g.Addresses, Organizations: g.Organizations,
		Title: g.Title, Role: g.Role, Timezone: g.Timezone, Geo: g.Geo, Categories: g.Categories, Notes: g.Notes,
		Urls: g.Urls, Source: g.Source, Prodid: g.Prodid, Fburl: g.Fburl, Caluri: g.Caluri, Caladruri: g.Caladruri,
		Photo: g.Photo, Logo: g.Logo, Sound: g.Sound, Key: g.Key, CustomFields: g.CustomFields,
		Favorite: g.Favorite, Archived: g.Archived, Deleted: g.Deleted, CreatedAt: g.CreatedAt,
		ParentIds: recordIDStrings(c.ParentIDs),
	}
}

func firstContact(results *[]surrealdb.QueryResult[[]dbContact]) *gql_model.Contact {
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return qr.Result[0].toGQL()
		}
	}
	return nil
}

// ── Writable fields ────────────────────────────────────────────────────────────

// ContactFields holds the writable surface. A nil pointer/slice means "absent"
// (left unchanged on update; omitted on create). An empty (non-nil) slice clears
// the list on update.
type ContactFields struct {
	UID           *string
	Kind          *string
	FormattedName *string
	Name          *NameData
	Nicknames     []string
	Birthday      *string
	Anniversary   *string
	Gender        *GenderData
	Emails        []FieldData
	Phones        []FieldData
	Impps         []FieldData
	Languages     []FieldData
	Addresses     []AddressData
	Organizations []OrgData
	Title         *string
	Role          *string
	Timezone      *string
	Geo           *GeoData
	Categories    []string
	Notes         []string
	Urls          []FieldData
	Source        *string
	Prodid        *string
	Fburl         *string
	Caluri        *string
	Caladruri     *string
	Photo         *models.RecordID
	Logo          *models.RecordID
	Sound         *models.RecordID
	Key           *models.RecordID
	CustomFields  []CustomFieldData
	Favorite      *bool
	Archived      *bool
	Deleted       *bool
}

// dataFieldNames is every versioned data column, in a stable order. The update /
// version SET clauses coalesce each with the current row (NULL param = unchanged).
var dataFieldNames = []string{
	"uid", "kind", "formatted_name", "name", "nicknames", "birthday", "anniversary", "gender",
	"emails", "phones", "impps", "languages", "addresses", "organizations", "title", "role",
	"timezone", "geo", "categories", "notes", "urls", "source", "prodid", "fburl", "caluri",
	"caladruri", "photo", "logo", "sound", "key", "custom_fields", "favorite", "archived", "deleted",
}

// nilable turns a typed nil pointer/slice into an untyped nil so the driver sends
// SurrealDB NULL (which `?? $current` then resolves to the unchanged value).
func slicePresent[T any](s []T) any {
	if s == nil {
		return nil
	}
	out := make([]any, len(s))
	for i := range s {
		out[i] = s[i]
	}
	return out
}

func ptrPresent[T any](p *T) any {
	if p == nil {
		return nil
	}
	return *p
}

// params maps every data field to its value (or nil when absent).
func (f *ContactFields) params() map[string]any {
	return map[string]any{
		"uid":            ptrPresent(f.UID),
		"kind":           ptrPresent(f.Kind),
		"formatted_name": ptrPresent(f.FormattedName),
		"name":           ptrPresent(f.Name),
		"nicknames":      slicePresent(f.Nicknames),
		"birthday":       ptrPresent(f.Birthday),
		"anniversary":    ptrPresent(f.Anniversary),
		"gender":         ptrPresent(f.Gender),
		"emails":         slicePresent(f.Emails),
		"phones":         slicePresent(f.Phones),
		"impps":          slicePresent(f.Impps),
		"languages":      slicePresent(f.Languages),
		"addresses":      slicePresent(f.Addresses),
		"organizations":  slicePresent(f.Organizations),
		"title":          ptrPresent(f.Title),
		"role":           ptrPresent(f.Role),
		"timezone":       ptrPresent(f.Timezone),
		"geo":            ptrPresent(f.Geo),
		"categories":     slicePresent(f.Categories),
		"notes":          slicePresent(f.Notes),
		"urls":           slicePresent(f.Urls),
		"source":         ptrPresent(f.Source),
		"prodid":         ptrPresent(f.Prodid),
		"fburl":          ptrPresent(f.Fburl),
		"caluri":         ptrPresent(f.Caluri),
		"caladruri":      ptrPresent(f.Caladruri),
		"photo":          ptrPresent(f.Photo),
		"logo":           ptrPresent(f.Logo),
		"sound":          ptrPresent(f.Sound),
		"key":            ptrPresent(f.Key),
		"custom_fields":  slicePresent(f.CustomFields),
		"favorite":       ptrPresent(f.Favorite),
		"archived":       ptrPresent(f.Archived),
		"deleted":        ptrPresent(f.Deleted),
	}
}

// coalesceSet builds "field = $field ?? $current.field, …" for every data field.
func coalesceSet() string {
	parts := make([]string, len(dataFieldNames))
	for i, name := range dataFieldNames {
		parts[i] = fmt.Sprintf("%s = $%s ?? $current.%s", name, name, name)
	}
	return strings.Join(parts, ",\n\t\t\t")
}

// createSet builds assignments only for the fields the caller actually set, so
// absent option fields default to NONE rather than being assigned NULL.
func (f *ContactFields) createSet() (string, map[string]any) {
	assignments := []string{}
	params := map[string]any{}
	for name, value := range f.params() {
		if value == nil {
			continue
		}
		assignments = append(assignments, fmt.Sprintf("%s = $%s", name, name))
		params[name] = value
	}
	return strings.Join(assignments, ", "), params
}

type CreateContactParams struct {
	UserID models.RecordID
	Fields ContactFields
}

type UpdateContactParams struct {
	ID               models.RecordID
	UserID           models.RecordID
	ParentVersionIDs []models.RecordID
	Fields           ContactFields
}

type ListVersionsParams struct {
	ContactID     models.RecordID
	FormattedName *string
	Before        *string
}

// ── CRUD ───────────────────────────────────────────────────────────────────────

func (store *ContactStore) Create(ctx context.Context, params *CreateContactParams) (*gql_model.Contact, error) {
	assignments, fieldParams := params.Fields.createSet()
	query := fmt.Sprintf(`
		BEGIN TRANSACTION;
		LET $contact_id = type::string(rand::uuid());
		LET $version = (CREATE ONLY contact_version SET
			contact_id = type::record("contact", $contact_id), user = $user, %[1]s);
		LET $contact = CREATE ONLY type::record("contact", $contact_id) SET
			user = $user, %[1]s, version = $version.id;
		RETURN [$contact];
		COMMIT TRANSACTION;
	`, assignments)

	fieldParams["user"] = params.UserID
	results, err := surrealdb.Query[[]dbContact](ctx, store.DB, query, fieldParams)
	if err != nil {
		return nil, fmt.Errorf("create contact: %w", err)
	}
	if c := firstContact(results); c != nil {
		return c, nil
	}
	return nil, fmt.Errorf("create contact: no result returned")
}

func (store *ContactStore) Update(ctx context.Context, params *UpdateContactParams) (*gql_model.Contact, error) {
	set := coalesceSet()
	query := fmt.Sprintf(`
		BEGIN TRANSACTION;
		LET $current = (SELECT * FROM contact WHERE id = $id AND user = $user LIMIT 1)[0];
		LET $new_version = (CREATE contact_version SET
			contact_id = $id, user = $current.user,
			%[1]s
		)[0];
		LET $plist = (IF array::len($parents) == 0 THEN [$current.version] ELSE $parents END);
		FOR $parent IN $plist {
			RELATE $parent->derived_from->$new_version.id;
		};
		LET $result = (UPDATE $id SET
			%[1]s,
			version = $new_version.id
		)[0];
		RETURN [$result];
		COMMIT TRANSACTION;
	`, set)

	// A nil slice marshals to NULL, which array::len() rejects; an empty array
	// makes the SQL fall back to the current head version as the lineage parent.
	parents := params.ParentVersionIDs
	if parents == nil {
		parents = []models.RecordID{}
	}
	queryParams := params.Fields.params()
	queryParams["id"] = params.ID
	queryParams["user"] = params.UserID
	queryParams["parents"] = parents
	results, err := surrealdb.Query[[]dbContact](ctx, store.DB, query, queryParams)
	if err != nil {
		return nil, fmt.Errorf("update contact: %w", err)
	}
	if c := firstContact(results); c != nil {
		return c, nil
	}
	return nil, ErrNotFound
}

// restoreSet builds "field = $src.field, …" copying every data field from a
// source version row into the new head.
func restoreSet() string {
	parts := make([]string, len(dataFieldNames))
	for i, name := range dataFieldNames {
		parts[i] = fmt.Sprintf("%s = $src.%s", name, name)
	}
	return strings.Join(parts, ",\n\t\t\t")
}

// RestoreVersion forks the lineage from an old version: it copies that version's
// content into a fresh head version whose only parent is the source version, so
// history branches rather than being overwritten.
func (store *ContactStore) RestoreVersion(ctx context.Context, id, versionID, userID models.RecordID) (*gql_model.Contact, error) {
	set := restoreSet()
	query := fmt.Sprintf(`
		BEGIN TRANSACTION;
		LET $current = (SELECT * FROM contact WHERE id = $id AND user = $user LIMIT 1)[0];
		LET $src = (SELECT * FROM contact_version WHERE id = $version AND contact_id = $id LIMIT 1)[0];
		LET $new_version = (CREATE contact_version SET
			contact_id = $id, user = $current.user,
			%[1]s
		)[0];
		FOR $parent IN [$version] {
			RELATE $parent->derived_from->$new_version.id;
		};
		LET $result = (UPDATE $id SET
			%[1]s,
			version = $new_version.id
		)[0];
		RETURN [$result];
		COMMIT TRANSACTION;
	`, set)

	results, err := surrealdb.Query[[]dbContact](ctx, store.DB, query, map[string]any{
		"id": id, "user": userID, "version": versionID,
	})
	if err != nil {
		return nil, fmt.Errorf("restore contact version: %w", err)
	}
	if c := firstContact(results); c != nil {
		return c, nil
	}
	return nil, ErrNotFound
}

// setFlags is a single-flag edit (trash/archive/favorite) that still records a
// version, deriving the lineage parent from the current head.
func (store *ContactStore) setFlags(ctx context.Context, id, user models.RecordID, fields ContactFields) (*gql_model.Contact, error) {
	return store.Update(ctx, &UpdateContactParams{ID: id, UserID: user, Fields: fields})
}

func boolPtr(b bool) *bool { return &b }

func (store *ContactStore) Trash(ctx context.Context, id, user models.RecordID) (*gql_model.Contact, error) {
	return store.setFlags(ctx, id, user, ContactFields{Deleted: boolPtr(true)})
}
func (store *ContactStore) Restore(ctx context.Context, id, user models.RecordID) (*gql_model.Contact, error) {
	return store.setFlags(ctx, id, user, ContactFields{Deleted: boolPtr(false)})
}
func (store *ContactStore) Archive(ctx context.Context, id, user models.RecordID) (*gql_model.Contact, error) {
	return store.setFlags(ctx, id, user, ContactFields{Archived: boolPtr(true)})
}
func (store *ContactStore) Unarchive(ctx context.Context, id, user models.RecordID) (*gql_model.Contact, error) {
	return store.setFlags(ctx, id, user, ContactFields{Archived: boolPtr(false)})
}
func (store *ContactStore) SetFavorite(ctx context.Context, id, user models.RecordID, favorite bool) (*gql_model.Contact, error) {
	return store.setFlags(ctx, id, user, ContactFields{Favorite: boolPtr(favorite)})
}

func (store *ContactStore) Delete(ctx context.Context, id, userID models.RecordID) error {
	_, err := surrealdb.Query[[]any](ctx, store.DB, `
		DELETE related WHERE in = $id OR out = $id;
		DELETE member WHERE in = $id OR out = $id;
		DELETE contact_version WHERE contact_id = $id;
		DELETE contact WHERE id = $id AND user = $user;
	`, map[string]any{"id": id, "user": userID})
	return err
}

func (store *ContactStore) Get(ctx context.Context, id, userID models.RecordID) (*gql_model.Contact, error) {
	results, err := surrealdb.Query[[]dbContact](ctx, store.DB,
		"SELECT * FROM contact WHERE id = $id AND user = $user LIMIT 1",
		map[string]any{"id": id, "user": userID})
	if err != nil {
		return nil, fmt.Errorf("get contact: %w", err)
	}
	contact := firstContact(results)
	if contact == nil {
		return nil, ErrNotFound
	}
	if err := store.loadRelations(ctx, id, contact); err != nil {
		return nil, err
	}
	return contact, nil
}

// listConditions builds the shared WHERE clause (ownership scope + favorite +
// search + structured filter) and its bound params. Used by both List and Count
// so they always select the same rows.
func listConditions(userID models.RecordID, scope gql_model.ContactScope, favorite *bool, search *string, filter *gql_model.ContactFilter) ([]string, map[string]any, error) {
	conditions := []string{"user = $user"}
	switch scope {
	case gql_model.ContactScopeActive:
		conditions = append(conditions, "deleted = false", "archived = false")
	case gql_model.ContactScopeArchived:
		conditions = append(conditions, "deleted = false", "archived = true")
	case gql_model.ContactScopeTrashed:
		conditions = append(conditions, "deleted = true")
	case gql_model.ContactScopeAll:
		// no flag filter
	}
	queryParams := map[string]any{"user": userID}
	if favorite != nil {
		conditions = append(conditions, "favorite = $favorite")
		queryParams["favorite"] = *favorite
	}
	// Server-side search across the formatted name, emails and phones. The needle
	// is lowercased in Go; field values are lowercased in SurrealQL.
	if search != nil && strings.TrimSpace(*search) != "" {
		conditions = append(conditions,
			"(string::lowercase(formatted_name) CONTAINS $search"+
				" OR array::len(emails[WHERE string::lowercase(value) CONTAINS $search]) > 0"+
				" OR array::len(phones[WHERE string::lowercase(value) CONTAINS $search]) > 0)")
		queryParams["search"] = strings.ToLower(strings.TrimSpace(*search))
	}
	// Structured field filter compiled to a WHERE expression with bound params.
	if filter != nil {
		compiler := newFilterCompiler()
		expr := contactFilterEngine.compile(compiler, filter)
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

// sortColumns whitelists the sortable enum values to real columns, so an ORDER
// BY clause can be built without interpolating arbitrary field names.
var sortColumns = map[gql_model.ContactSortField]string{
	gql_model.ContactSortFieldFormattedName: "formatted_name",
	gql_model.ContactSortFieldCreatedAt:     "created_at",
	gql_model.ContactSortFieldUpdatedAt:     "updated_at",
	gql_model.ContactSortFieldBirthday:      "birthday",
}

// orderByClause builds "ORDER BY col [DESC], …" from the sort keys, defaulting to
// formatted_name ascending when none are given.
func orderByClause(sort []*gql_model.ContactSort) (string, error) {
	if len(sort) == 0 {
		return "ORDER BY formatted_name", nil
	}
	parts := make([]string, 0, len(sort))
	for _, key := range sort {
		col, ok := sortColumns[key.Field]
		if !ok {
			return "", fmt.Errorf("unsortable field %q", key.Field)
		}
		clause := col
		if key.Direction != nil && *key.Direction == gql_model.SortDirectionDesc {
			clause += " DESC"
		}
		parts = append(parts, clause)
	}
	return "ORDER BY " + strings.Join(parts, ", "), nil
}

func (store *ContactStore) List(ctx context.Context, userID models.RecordID, scope gql_model.ContactScope, favorite *bool, search *string, filter *gql_model.ContactFilter, sort []*gql_model.ContactSort, limit, offset int) ([]*gql_model.Contact, error) {
	conditions, queryParams, err := listConditions(userID, scope, favorite, search, filter)
	if err != nil {
		return nil, err
	}
	orderBy, err := orderByClause(sort)
	if err != nil {
		return nil, err
	}
	queryParams["limit"] = limit
	queryParams["offset"] = offset
	query := "SELECT * FROM contact WHERE " + strings.Join(conditions, " AND ") +
		" " + orderBy + " LIMIT $limit START $offset"

	results, err := surrealdb.Query[[]dbContact](ctx, store.DB, query, queryParams)
	if err != nil {
		return nil, fmt.Errorf("list contacts: %w", err)
	}
	for _, qr := range *results {
		out := make([]*gql_model.Contact, len(qr.Result))
		for i := range qr.Result {
			out[i] = qr.Result[i].toGQL()
		}
		return out, nil
	}
	return nil, nil
}

// Count returns the number of contacts matching the same scope/favorite/search/
// filter as List, ignoring paging.
func (store *ContactStore) Count(ctx context.Context, userID models.RecordID, scope gql_model.ContactScope, favorite *bool, search *string, filter *gql_model.ContactFilter) (int, error) {
	conditions, queryParams, err := listConditions(userID, scope, favorite, search, filter)
	if err != nil {
		return 0, err
	}
	query := "SELECT count() AS count FROM contact WHERE " + strings.Join(conditions, " AND ") + " GROUP ALL"

	results, err := surrealdb.Query[[]struct {
		Count int `json:"count"`
	}](ctx, store.DB, query, queryParams)
	if err != nil {
		return 0, fmt.Errorf("count contacts: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return qr.Result[0].Count, nil
		}
	}
	return 0, nil
}

func (store *ContactStore) ListVersions(ctx context.Context, params *ListVersionsParams) ([]*gql_model.ContactVersion, error) {
	conditions := []string{"contact_id = $contact_id"}
	queryParams := map[string]any{"contact_id": params.ContactID}
	if params.FormattedName != nil {
		conditions = append(conditions, "formatted_name = $formatted_name")
		queryParams["formatted_name"] = *params.FormattedName
	}
	if params.Before != nil {
		conditions = append(conditions, "created_at <= <datetime>$before")
		queryParams["before"] = *params.Before
	}
	query := "SELECT *, <-derived_from<-contact_version AS parent_ids FROM contact_version WHERE " +
		strings.Join(conditions, " AND ") + " ORDER BY created_at DESC"

	results, err := surrealdb.Query[[]dbContact](ctx, store.DB, query, queryParams)
	if err != nil {
		return nil, fmt.Errorf("list contact versions: %w", err)
	}
	for _, qr := range *results {
		out := make([]*gql_model.ContactVersion, len(qr.Result))
		for i := range qr.Result {
			out[i] = qr.Result[i].toVersionGQL()
		}
		return out, nil
	}
	return nil, nil
}

// ── Graph relations (RELATED / MEMBER) ─────────────────────────────────────────

type relationRow struct {
	Out   *models.RecordID `json:"out,omitempty"`
	Types []string         `json:"types,omitempty"`
	Pref  *int             `json:"pref,omitempty"`
}

func (store *ContactStore) loadRelations(ctx context.Context, id models.RecordID, contact *gql_model.Contact) error {
	related, err := surrealdb.Query[[]relationRow](ctx, store.DB,
		"SELECT out, types, pref FROM related WHERE in = $id", map[string]any{"id": id})
	if err != nil {
		return fmt.Errorf("load relations: %w", err)
	}
	for _, qr := range *related {
		for _, row := range qr.Result {
			contact.Related = append(contact.Related, &gql_model.ContactRelation{
				ContactID: recordIDString(row.Out), Types: row.Types, Pref: row.Pref,
			})
		}
		break
	}

	members, err := surrealdb.Query[[]relationRow](ctx, store.DB,
		"SELECT out FROM member WHERE in = $id", map[string]any{"id": id})
	if err != nil {
		return fmt.Errorf("load members: %w", err)
	}
	for _, qr := range *members {
		for _, row := range qr.Result {
			contact.MemberIds = append(contact.MemberIds, recordIDString(row.Out))
		}
		break
	}
	return nil
}

// ownsBoth verifies the caller owns both endpoints before linking them.
func (store *ContactStore) ownsBoth(ctx context.Context, user, a, b models.RecordID) (bool, error) {
	results, err := surrealdb.Query[[]dbContact](ctx, store.DB,
		"SELECT id FROM contact WHERE user = $user AND id IN [$a, $b]",
		map[string]any{"user": user, "a": a, "b": b})
	if err != nil {
		return false, err
	}
	for _, qr := range *results {
		return len(qr.Result) == 2, nil
	}
	return false, nil
}

func (store *ContactStore) Relate(ctx context.Context, user, from, to models.RecordID, types []string, pref *int) (bool, error) {
	ok, err := store.ownsBoth(ctx, user, from, to)
	if err != nil || !ok {
		return false, err
	}
	// option<T> edge fields reject NULL, so only SET the ones the caller provided.
	sets := []string{}
	params := map[string]any{"from": from, "to": to}
	if types != nil {
		sets = append(sets, "types = $types")
		params["types"] = types
	}
	if pref != nil {
		sets = append(sets, "pref = $pref")
		params["pref"] = *pref
	}
	relate := "RELATE $from->related->$to"
	if len(sets) > 0 {
		relate += " SET " + strings.Join(sets, ", ")
	}
	_, err = surrealdb.Query[[]any](ctx, store.DB,
		"DELETE related WHERE in = $from AND out = $to; "+relate+";", params)
	return err == nil, err
}

func (store *ContactStore) Unrelate(ctx context.Context, user, from, to models.RecordID) (bool, error) {
	_, err := surrealdb.Query[[]any](ctx, store.DB,
		"DELETE related WHERE in = $from AND out = $to AND in.user = $user",
		map[string]any{"from": from, "to": to, "user": user})
	return err == nil, err
}

func (store *ContactStore) AddMember(ctx context.Context, user, group, member models.RecordID) (bool, error) {
	ok, err := store.ownsBoth(ctx, user, group, member)
	if err != nil || !ok {
		return false, err
	}
	_, err = surrealdb.Query[[]any](ctx, store.DB,
		"DELETE member WHERE in = $group AND out = $member; RELATE $group->member->$member;",
		map[string]any{"group": group, "member": member})
	return err == nil, err
}

func (store *ContactStore) RemoveMember(ctx context.Context, user, group, member models.RecordID) (bool, error) {
	_, err := surrealdb.Query[[]any](ctx, store.DB,
		"DELETE member WHERE in = $group AND out = $member AND in.user = $user",
		map[string]any{"group": group, "member": member, "user": user})
	return err == nil, err
}
