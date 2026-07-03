-- Renamed the "org" client_table kind to "internal". Now that each organization
-- has its own dedicated SurrealDB instance, an org-owned table needs no
-- organization_id owner column (the whole instance is the org) — "internal" names
-- that: no per-user author, no owner column, readable/writable by the org's own
-- clients. Update the client_table.kind ASSERT to the new set.
DEFINE FIELD OVERWRITE kind ON client_table TYPE string
    ASSERT $value IN ["data", "relation", "helper", "internal"] READONLY;
