-- First-party OAuth clients. All are public PKCE clients with no secret. Native
-- builds redirect to a custom scheme, browser builds to a localhost route and to
-- the dev and prod hosts. The MCP's loopback callback (NW_MCP_REDIRECT_PORT,
-- default 8765) is registered on every client so `login` works with any of them.
--
-- A collection scope `<collection>:read|write` is the ceiling for the role any
-- access grant gives the token: the API caps the grant's role by it.

-- neoworks.dev web dashboard (connected apps, devices)
CREATE client CONTENT {
    id:                "neoworks.dev",
    name:              "Neoworks",
    secret_hash:       NONE,
    redirect_uris:     [
        "http://neoworks.localhost/auth/callback",
        "https://neoworks.localhost/auth/callback",
        "https://neoworks.dev/auth/callback",
        "http://127.0.0.1:8765/callback"
    ],
    scopes:            ["openid", "profile", "email"],
    auto_grant_scopes: true,
    public:            true
};

-- Authenticator (Capacitor)
CREATE client CONTENT {
    id:                "neoworks-authenticator",
    name:              "Neoworks Authenticator",
    secret_hash:       NONE,
    redirect_uris:     [
        "dev.neoworks.neo://callback",
        "http://localhost:5173/callback",
        "http://127.0.0.1:8765/callback"
    ],
    scopes:            ["openid", "profile", "email"],
    auto_grant_scopes: true,
    public:            true
};

CREATE client CONTENT {
    id:                "neoworks-calendar",
    name:              "Neoworks Calendar",
    secret_hash:       NONE,
    redirect_uris:     [
        "dev.neoworks.calendar://callback",
        "http://localhost:5175/callback",
        "https://calendar.neoworks.localhost/callback",
        "https://calendar.neoworks.dev/callback",
        "http://127.0.0.1:8765/callback"
    ],
    scopes:            [
        "openid", "profile", "email",
        "calendar:read", "calendar:write",
        "google:read", "google:write"
    ],
    auto_grant_scopes: true,
    public:            true
};

CREATE client CONTENT {
    id:                "neoworks-contacts",
    name:              "Neoworks Contacts",
    secret_hash:       NONE,
    redirect_uris:     [
        "dev.neoworks.contacts://callback",
        "http://localhost:5176/callback",
        "https://contacts.neoworks.localhost/callback",
        "https://contacts.neoworks.dev/callback",
        "http://127.0.0.1:8765/callback"
    ],
    scopes:            ["openid", "profile", "email", "contacts:read", "contacts:write"],
    auto_grant_scopes: true,
    public:            true
};

CREATE client CONTENT {
    id:                "neoworks-photos",
    name:              "Neoworks Photos",
    secret_hash:       NONE,
    redirect_uris:     [
        "dev.neoworks.photos://callback",
        "http://localhost:5177/callback",
        "https://photos.neoworks.localhost/callback",
        "https://photos.neoworks.dev/callback",
        "http://127.0.0.1:8765/callback"
    ],
    scopes:            ["openid", "profile", "email", "photos:read", "photos:write"],
    auto_grant_scopes: true,
    public:            true
};

CREATE client CONTENT {
    id:                "neoworks-files",
    name:              "Neoworks Files",
    secret_hash:       NONE,
    redirect_uris:     [
        "dev.neoworks.files://callback",
        "http://localhost:5183/callback",
        "https://files.neoworks.localhost/callback",
        "https://files.neoworks.dev/callback",
        "http://127.0.0.1:8765/callback"
    ],
    scopes:            ["openid", "profile", "email", "files:read", "files:write"],
    auto_grant_scopes: true,
    public:            true
};

-- SDK demo (apps/sdk-demo): reference app for libneoworks, holds every collection.
CREATE client CONTENT {
    id:                "sdk-demo",
    name:              "SDK Demo",
    secret_hash:       NONE,
    redirect_uris:     [
        "http://localhost:5180/callback",
        "https://sdk-demo.neoworks.localhost/callback",
        "https://sdk-demo.neoworks.dev/callback",
        "http://127.0.0.1:8765/callback"
    ],
    scopes:            [
        "openid", "profile", "email",
        "calendar:read", "calendar:write",
        "contacts:read", "contacts:write",
        "photos:read", "photos:write",
        "files:read", "files:write"
    ],
    auto_grant_scopes: true,
    public:            true
};
