-- The SDK demo (apps/sdk-demo) is the reference app for the encrypted
-- collections, so it needs the same grants as the first-party clients that hold
-- them. 051 seeds it with the OIDC scopes only, which leaves every encrypted
-- surface unreachable: the Vault derives a per-collection keypair for each label
-- the caller's token carries, so a missing scope is a key it never derives, not
-- a flag it declines to honour.
UPDATE client SET scopes += [
    "contacts:read", "contacts:write",
    "calendar:read", "calendar:write",
    "memories:read", "memories:write"
] WHERE id = client:⟨sdk-demo⟩;
