-- NeoWorks Photos (Capacitor + browser). Photos are user/org-scoped, authorised
-- by the bearer token at the resolver layer, so no data scopes are needed.
-- Public client with no secret; native builds redirect to a custom scheme,
-- browser/dev builds to a localhost route (and the https caddy domain).
CREATE client CONTENT {
    id:                "neoworks-photos",
    organization:      organization:neoworks,
    secret_hash:       NONE,
    redirect_uris:     [
        "dev.neoworks.photos://callback",
        "http://localhost:5177/callback",
        "https://photos.neoworks.localhost/callback"
    ],
    scopes:            ["openid", "profile", "email", "photos:read", "photos:write", "legacy:read"],
    auto_grant_scopes: true,
    public:            true
};
