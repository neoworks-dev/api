
-- Seed script for local development
-- Run with: surreal import --conn http://localhost:8000 --user root --pass root --ns neoworks --db auth seed.surql

-- Internal client for neoworks.dev frontend
CREATE client CONTENT {
    id:                "neoworks.dev",
    secret_hash:       NONE,
    redirect_uris:     ["http://neoworks.localhost/auth/callback"],
    scopes:            ["openid", "profile", "email", "tokens:read"],
    auto_grant_scopes: true,
    public:            true
};
