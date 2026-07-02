-- OpenSchema public registry site (openschema.neoworks.dev). Server-side PKCE:
-- the SvelteKit server exchanges the code and keeps the refresh token in an
-- HttpOnly cookie. Public client with no secret. Dev + prod redirect URIs are
-- seeded together so flipping BASE_DOMAIN doesn't break redirect validation.
CREATE client CONTENT {
    id:                "openschema",
    organization:      organization:neoworks,
    secret_hash:       NONE,
    redirect_uris:     [
        "https://openschema.neoworks.localhost/auth/callback",
        "https://openschema.neoworks.dev/auth/callback"
    ],
    scopes:            ["openid", "profile", "email"],
    auto_grant_scopes: true,
    public:            true
};
