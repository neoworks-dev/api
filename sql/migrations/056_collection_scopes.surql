-- Grant the E2EE collection scopes to the first-party clients that need them.
-- The Vault's capability gate derives per-scope keypairs only for labels the
-- caller's token carries (scope-keys.js), so an encrypted collection is
-- unreadable without <collection>:read and unwritable without
-- <collection>:write — the scope IS the crypto boundary, not a policy flag.
UPDATE client SET scopes += ["contacts:read", "contacts:write"]
    WHERE id = client:⟨neoworks-contacts⟩;

UPDATE client SET scopes += ["calendar:read", "calendar:write"]
    WHERE id = client:⟨neoworks-calendar⟩;

-- neoworks.dev is also the integration-test client, so it carries all three.
UPDATE client SET scopes += [
    "contacts:read", "contacts:write",
    "calendar:read", "calendar:write",
    "memories:read", "memories:write"
] WHERE id = client:⟨neoworks.dev⟩;
