-- NeoWorks Maps (Capacitor + browser). A CONFIDENTIAL client: it authenticates
-- the token exchange with a client_secret (no PKCE). The secret_hash below is a
-- bcrypt hash; the plaintext secret lives in apps/maps env VITE_MAPS_CLIENT_SECRET.
-- Maps content (reports, reviews) is user-scoped, authorised by the bearer token
-- at the maps-api resolver layer, so no data scopes are needed.
CREATE client CONTENT {
    id:                "neoworks-maps",
    organization:      organization:neoworks,
    secret_hash:       "$2a$10$1cT79BEJB3R8M57pggkHc.vRE67zsL.0AzXLyxQ/ThpMdSV7d40zq",
    redirect_uris:     [
        "dev.neoworks.maps://callback",
        "http://localhost:5181/callback",
        "https://maps.neoworks.localhost/callback"
    ],
    scopes:            ["openid", "profile", "email"],
    auto_grant_scopes: true,
    public:            false
};
