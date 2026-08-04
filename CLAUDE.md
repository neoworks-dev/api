# Optional / Nullable Fields

Handle absent values in Go, not in SurrealQL.

The driver marshals a Go `nil` to SurrealDB `NULL`, but `option<T>` fields are
`none | T` and reject `NULL`. When a value is absent, **omit the field from the
`SET` clause entirely** so it defaults to `NONE` — build the assignment list and
params map conditionally:

```go
assignments := []string{"name = $name", ...}
params := map[string]any{"name": ..., ...}
if rt.subjectPath != "" {
    assignments = append(assignments, "subject_path = $subject_path")
    params["subject_path"] = rt.subjectPath
}
query := "CREATE client_table SET " + strings.Join(assignments, ", ")
```

Do NOT paper over this in SurrealQL with coalescing (`$x ?? NONE`). The query
should not compensate for values the Go code shaped wrong.

# Versioning Pattern

Versioned entities use three components:

## Tables

**`<entity>` (current state)**
- Holds all data fields directly (no joins needed for reads)
- `version` field points to the current `<entity>_version` record
- `created_at`: `VALUE $before OR time::now() READONLY` — set once, never changes
- `updated_at`: `VALUE time::now()` — mutable, updated on every write
- `user` (or owner field): `READONLY`

**`<entity>_version` (append-only history)**
- All fields `READONLY` — rows are never mutated after insert
- Mirrors all data fields from the main table
- `<entity>_id`: back-reference to the parent entity
- `created_at`: `VALUE time::now() READONLY` — records exactly when this version was created

**`derived_from` (shared relation)**
- `TYPE RELATION` with no IN/OUT type constraint — shared across all versioned entities
- Connects `old_version -> derived_from -> new_version`
- Enables graph traversal for full version ancestry

## Write Operations

**Create**
```sql
BEGIN TRANSACTION;
LET $entity = (CREATE <entity> SET user = $user, <fields...>)[0];
LET $version = (CREATE <entity>_version SET <entity>_id = $entity.id, user = $user, <fields...>)[0];
LET $result = (UPDATE $entity.id SET version = $version.id)[0];
RETURN $result;
COMMIT TRANSACTION;
```

**Update**

The caller must supply `parentVersionIds` (1 for a normal edit, 2 for a merge). The graph is built by the caller, not inferred from the current head, so non-linear history is fully supported.

```sql
BEGIN TRANSACTION;
LET $current = (SELECT * FROM <entity> WHERE id = $id LIMIT 1)[0];
LET $new_version = (CREATE <entity>_version SET
    <entity>_id = $id,
    field = $new_value ?? $current.field, ...
)[0];
FOR $parent IN $parents {
    RELATE $parent->derived_from->$new_version.id;
};
LET $result = (UPDATE $id SET field = $new_value ?? $current.field, ..., version = $new_version.id)[0];
RETURN $result;
COMMIT TRANSACTION;
```

## Current entities using this pattern
- `contact` / `contact_version`
- `media` / `media_version`

# Canonical Entity Surface

Versioning is one capability in a larger contract for how all entities are
queried and mutated: base CRUD + opt-in capabilities (Queryable, SoftDeletable,
Versioned, Related, Subscribable, Bulk) crossed by ownership-scope / validation /
media-ref axes. The aim is to define each capability once (entity-generic Go store
+ filter compiler, shared GraphQL primitives, SDK base) so entities stay
consistent and new ones get a full surface for free. Spec + roadmap:
see the `/docs/api/entity-surface` page in the web app
(`apps/web/src/routes/(public)/docs/api/entity-surface/+page.svx`).

Implemented so far:
- **Filter compiler is entity-generic** — `storage/database/filter_compiler.go`
  holds the operator logic (string/bool/int/date/stringList/fieldList/geo) plus a
  generic `boolFilter[F]` engine for the and/or/not tree. Each entity adds a tiny
  wiring file mapping its filter fields to columns: `contact_filter.go`,
  `event_filter.go`. To filter a new entity, define its `XFilter` reusing the
  shared inputs and add a `boolFilter[XFilter]` value.
- **Shared GraphQL primitives** live in `schema/shared.graphql` (StringFilter,
  BoolFilter, IntFilter, DateFilter, StringListFilter, GeoFilter, NearInput,
  SortDirection). Per-entity `XFilter`/sort inputs reference them.
- **Contacts** have the full Queryable surface: `contacts(filter, sort, …)` +
  `contactCount`. FTS lives behind a FULLTEXT index (migrations 039/040);
  `StringFilter.search` is `@@`, `fuzzy` is `string::similarity::fuzzy`.
- **Events** have a structured `EventFilter` on the `events` query (reuses the
  compiler; `start` maps to the `start_time` column).

Not yet done: a generic `VersionedStore[Row]` (contact is still the only
versioned store of this shape; deferred until a second one needs it), and the
remaining capabilities (diff/merge/lineage nav, relation edit/traverse, bulk,
real-time).
