-- Dev convenience for the local MCP server (packages/mcp, bin `nw-mcp`).
--
-- 1) Seeds a root user that OWNS organization:neoworks. That org owns every
--    first-party client, so this account is the single identity to log in with.
-- 2) Adds the MCP's loopback OAuth callback to every client owned by that org, so
--    `login(clientId)` can complete for any of them. The OAuth server matches
--    redirect_uri by EXACT string, so the callback must be registered verbatim.
--
-- Login is bcrypt (apps/oauth/handlers/auth/login.go); only user.password_hash is
-- seeded. The E2EE key material (user_key/device) is intentionally NOT seeded — the
-- MCP's token-based reads never touch the vault.
--
-- Credentials:  root@neoworks.dev  /  neoworks
-- CHANGE THE PASSWORD before running anywhere but local dev.

CREATE user:root CONTENT {
    first_name:    "Root",
    last_name:     "Neoworks",
    email:         "root@neoworks.dev",
    password_hash: "$2a$10$mgB0Zcd9ebqZp3uXnZWyVun4FOyoUJpudH5LhmsOj7DuNniFxTsxG"
};

-- Owner membership → root can act across the org that owns all first-party clients.
RELATE user:root->membership->organization:neoworks SET role = "owner";

-- Loopback callback for the MCP (NW_MCP_REDIRECT_PORT defaults to 8765). Appended to
-- every first-party client so `login` works whichever client you authenticate as.
UPDATE client
    SET redirect_uris += "http://127.0.0.1:8765/callback"
    WHERE organization = organization:neoworks;
