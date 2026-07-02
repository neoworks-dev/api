-- Island (native Android accessibility overlay). Public client, custom-scheme
-- redirect for the authorization-code + PKCE flow. Contacts are user-scoped,
-- authorised by the bearer token at the resolver layer, so no data scopes needed.
CREATE client CONTENT {
    id:                "island",
    organization:      organization:neoworks,
    secret_hash:       NONE,
    redirect_uris:     ["dev.neoworks.island://callback"],
    scopes:            ["openid", "profile", "email"],
    auto_grant_scopes: true,
    public:            true
};
