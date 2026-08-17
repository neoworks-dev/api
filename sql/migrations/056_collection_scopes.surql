-- Grant the E2EE collection scopes to the first-party clients that need them.
-- The Vault's capability gate derives per-scope keypairs only for labels the
-- caller's token carries (scope-keys.js), so an encrypted collection is
-- unreadable without <collection>:read and unwritable without
-- <collection>:write — the scope IS the crypto boundary, not a policy flag.
UPDATE client SET scopes += ["contacts:read", "contacts:write"]
    WHERE id = client:⟨neoworks-contacts⟩;

UPDATE client SET scopes += ["calendar:read", "calendar:write"]
    WHERE id = client:⟨neoworks-calendar⟩;

-- muse holds memories. ai:embed lets the Vault turn their text into search
-- vectors on the user's own machine; without it recall falls back to substring
-- matching, which is a degraded search rather than a broken one.
UPDATE client SET scopes += ["memories:read", "memories:write", "ai:embed"]
    WHERE id = client:⟨muse⟩;

-- neoworks.dev is also the integration-test client, so it carries all three.
UPDATE client SET scopes += [
    "contacts:read", "contacts:write",
    "calendar:read", "calendar:write",
    "memories:read", "memories:write",
    "ai:embed"
] WHERE id = client:⟨neoworks.dev⟩;
