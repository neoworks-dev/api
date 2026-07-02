
DEFINE TABLE client SCHEMAFULL
    PERMISSIONS NONE;

DEFINE FIELD id               ON client TYPE string ASSERT $value != NONE;
DEFINE FIELD secret_hash      ON client TYPE option<string>;
DEFINE FIELD redirect_uris    ON client TYPE array<string> DEFAULT [];
DEFINE FIELD scopes           ON client TYPE array<string> DEFAULT [];
DEFINE FIELD auto_grant_scopes ON client TYPE bool DEFAULT false;
DEFINE FIELD public           ON client TYPE bool DEFAULT false;

-- A public client must not have a secret
DEFINE INDEX client_id ON client FIELDS id UNIQUE;
