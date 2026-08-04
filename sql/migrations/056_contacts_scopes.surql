-- Grant the contacts encryption scopes to the first-party clients that need
-- them. The Vault's capability gate derives per-scope keypairs only for labels
-- the caller's token carries (scope-keys.js), so E2EE contacts require
-- contacts:read / contacts:write in the client's allowed scopes.
UPDATE client SET scopes += ["contacts:read", "contacts:write"]
    WHERE id = client:⟨neoworks-contacts⟩;

-- neoworks.dev is also the integration-test client.
UPDATE client SET scopes += ["contacts:read", "contacts:write"]
    WHERE id = client:⟨neoworks.dev⟩;
