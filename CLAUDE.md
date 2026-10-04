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

## Where this pattern does not apply

End-to-end encrypted data (the node tree) does not use it. Nodes version through
`node` / `node_version` (`sql/migrations/003_nodes.surql`): every accepted write
appends a full snapshot, and the server never reads content, so it builds no
`derived_from` graph. See `storage/database/node_push.go`.

# Node access rules

- A request acts as a principal: `install:<id>` when the token carries an install,
  otherwise `user:<id>` (`middleware/principal.go`). The token's collection scopes
  cap a grant's role: `<collection>:read` allows read, `<collection>:write` allows
  the grant's own role up to admin (`access/`).
- Authorization for a write is evaluated inside the push transaction, together
  with the `base_seq` check, so a grant revoked mid-request is seen by the write.
- Every seq (node writes, grant changes) comes from `fn::next_seq()`, one counter
  row, so commit order equals seq order and a pull cursor never skips a change.
- Node, grant and log rows use the contract's snake_case fields with plain string
  ids (`owner_id`, `parent_id`, `node_id`), because the oauth service writes roots
  and grants directly. `seq` on `node` and `access_grant` is assigned by the
  counter on create whatever the writer supplies.
- SurrealQL silently evaluates an undefined `$param` as NONE. Every parameter a
  statement names must be bound; `statement_params_test.go` checks each statement
  builder, so add new ones there.
