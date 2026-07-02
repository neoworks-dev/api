-- Grant the photos client the encryption scopes the scope-bound pipeline uses:
-- photos:read / photos:write gate decryption of new per-scope objects, and
-- legacy:read lets this first-party app read pre-migration objects (sealed under
-- the legacy account key). Idempotent via array::distinct. Applied to existing
-- DBs alongside the updated seed in 024.
UPDATE client:`neoworks-photos` SET scopes = array::distinct(array::concat(scopes, [
    "photos:read",
    "photos:write",
    "legacy:read"
]));
