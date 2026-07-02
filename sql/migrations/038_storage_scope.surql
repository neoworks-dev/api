-- Grant the neoworks.dev frontend the storage:read scope, gating the
-- storageUsage query that backs the dashboard storage widget. The client
-- auto-grants its scopes, so existing sessions pick this up on the next token
-- refresh. Idempotent via array::distinct. Applied alongside the updated seed
-- in 015.
UPDATE client:`neoworks.dev` SET scopes = array::distinct(array::concat(scopes, [
    "storage:read"
]));
