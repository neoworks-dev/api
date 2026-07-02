-- NeoWorks Chat (Capacitor + browser). Messages are end-to-end encrypted and
-- relayed via the standalone chat-relay service; the API only holds the X3DH
-- prekey keystore and the encrypted backup. No data scopes are needed.
-- Public client with no secret; native builds redirect to a custom scheme,
-- browser/dev builds to a localhost route (and the https caddy domain).
CREATE client CONTENT {
    id:                "neoworks-chat",
    organization:      organization:neoworks,
    secret_hash:       NONE,
    redirect_uris:     [
        "dev.neoworks.chat://callback",
        "http://localhost:5179/callback",
        "https://chat.neoworks.localhost/callback"
    ],
    scopes:            ["openid", "profile", "email"],
    auto_grant_scopes: true,
    public:            true
};
