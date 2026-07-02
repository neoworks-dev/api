-- The data plane's ownership model replaced the "shared" kind with "org":
-- org-scoped rows are owned by the organization that owns the requesting client
-- (not a per-row user author). Update the client_table.kind ASSERT to match.
-- Read visibility (private/shared/public) is a separate axis carried in
-- validated_schema, not constrained here.
DEFINE FIELD OVERWRITE kind ON client_table TYPE string
    ASSERT $value IN ["data", "relation", "helper", "org"] READONLY;
