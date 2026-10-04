-- First-party OAuth clients owned by organization:neoworks (seeded in 002).
-- Public clients with no secret; native builds redirect to a custom scheme,
-- browser/dev builds to a localhost route.

-- neoworks.dev frontend
CREATE client CONTENT {
    id:                "neoworks.dev",
    organization:      organization:neoworks,
    secret_hash:       NONE,
    redirect_uris:     [
        "http://neoworks.localhost/auth/callback",
        "https://neoworks.localhost/auth/callback"
    ],
    scopes:            ["openid", "profile", "email", "tokens:read", "storage:read"],
    auto_grant_scopes: true,
    public:            true
};

-- NeoWorks Authenticator (Capacitor)
CREATE client CONTENT {
    id:                "neoworks-authenticator",
    organization:      organization:neoworks,
    secret_hash:       NONE,
    redirect_uris:     ["dev.neoworks.neo://callback", "http://localhost:5173/callback"],
    scopes:            ["openid", "profile", "email"],
    auto_grant_scopes: true,
    public:            true
};

-- NeoWorks Calendar (Capacitor + browser). Org calendar access is authorised by
-- organization membership at the resolver layer, so no data scopes are needed.
CREATE client CONTENT {
    id:                "neoworks-calendar",
    organization:      organization:neoworks,
    secret_hash:       NONE,
    redirect_uris:     [
        "dev.neoworks.calendar://callback",
        "http://localhost:5175/callback",
        "https://calendar.neoworks.localhost/callback"
    ],
    scopes:            ["openid", "profile", "email"],
    auto_grant_scopes: true,
    public:            true
};

-- NeoWorks Contacts (Capacitor + browser). Contacts are user-scoped, authorised
-- by the bearer token at the resolver layer, so no data scopes are needed.
CREATE client CONTENT {
    id:                "neoworks-contacts",
    organization:      organization:neoworks,
    secret_hash:       NONE,
    redirect_uris:     [
        "dev.neoworks.contacts://callback",
        "http://localhost:5176/callback",
        "https://contacts.neoworks.localhost/callback"
    ],
    scopes:            ["openid", "profile", "email"],
    auto_grant_scopes: true,
    public:            true
};
