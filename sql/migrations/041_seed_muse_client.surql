-- Muse (apps/muse): Electron desktop + browser SPA. Public PKCE client with no
-- secret. Canvas/AI data lives in a self-provisioned client_database on the
-- JWT-scoped data plane, so no data scopes are needed. Electron dev loads the
-- Vite server on :5174; browser dev/prod go through Caddy. Dev + prod redirect
-- URIs are seeded together so flipping BASE_DOMAIN doesn't break redirect
-- validation.
CREATE client CONTENT {
    id:                "muse",
    organization:      organization:neoworks,
    secret_hash:       NONE,
    redirect_uris:     [
        "http://localhost:5174/auth/callback",
        "https://muse.neoworks.localhost/auth/callback",
        "https://muse.neoworks.dev/auth/callback"
    ],
    scopes:            ["openid", "profile", "email"],
    auto_grant_scopes: true,
    public:            true
};
