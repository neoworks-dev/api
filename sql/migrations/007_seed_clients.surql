-- First-party OAuth clients. All are public PKCE clients with no secret. Native
-- builds redirect to a custom scheme, browser builds to a localhost route and to
-- the dev and prod hosts. The MCP's loopback callback (NW_MCP_REDIRECT_PORT,
-- default 8765) is registered on every client so `login` works with any of them.
--
-- A collection scope `<collection>:read|write` is the ceiling for the role any
-- access grant gives the token: the API caps the grant's role by it.
-- `<collection>:share` lets the app share that collection with other people; the
-- consent screen offers it as a separate, unchecked permission.

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
        "calendar:read", "calendar:write", "calendar:share",
        "contacts:read",
        "google:read", "google:write", "google:share"
    ],
    auto_grant_scopes: true,
    public:            true
};

CREATE client CONTENT {
    id:                "neoworks-calendar-native",
    name:              "Neoworks Calendar",
    secret_hash:       NONE,
    redirect_uris:     [
        "neoworks-calendar://callback"
    ],
    scopes:            [
        "openid", "profile", "email",
        "calendar:read", "calendar:write", "calendar:share",
        "contacts:read",
        "google:read", "google:write", "google:share"
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
    scopes:            ["openid", "profile", "email", "contacts:read", "contacts:write", "contacts:share"],
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
    scopes:            ["openid", "profile", "email", "photos:read", "photos:write", "photos:share", "contacts:read"],
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
    scopes:            ["openid", "profile", "email", "files:read", "files:write", "files:share"],
    auto_grant_scopes: true,
    public:            true
};

-- OpenSchema registry site. `schemas:publish` lets the signed-in user publish
-- schema versions; reading the registry needs no token.
CREATE client CONTENT {
    id:                "openschema",
    name:              "OpenSchema",
    secret_hash:       NONE,
    redirect_uris:     [
        "http://localhost:5178/auth/callback",
        "https://openschema.neoworks.localhost/auth/callback",
        "https://openschema.neoworks.dev/auth/callback",
        "http://127.0.0.1:8765/callback"
    ],
    scopes:            ["openid", "profile", "email", "schemas:publish"],
    auto_grant_scopes: true,
    public:            true
};
