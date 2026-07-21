-- SDK demo (apps/sdk-demo): a bare, unstyled reference app showing how the SDK is
-- wired and what each resource can do. Public PKCE client with no secret. Dev
-- redirect URIs for the plain Vite server (:5173) plus the Caddy dev/prod hosts
-- are seeded together so flipping BASE_DOMAIN doesn't break redirect validation.
CREATE client CONTENT {
    id:                "sdk-demo",
    name:              "SDK Demo",
    organization:      organization:neoworks,
    secret_hash:       NONE,
    redirect_uris:     [
        "http://localhost:5180/callback",
        "https://sdk-demo.neoworks.localhost/callback",
        "https://sdk-demo.neoworks.dev/callback"
    ],
    scopes:            ["openid", "profile", "email"],
    auto_grant_scopes: true,
    public:            true
};
