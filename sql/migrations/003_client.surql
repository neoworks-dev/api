-- A client is an application or website that uses Neoworks for auth/storage/compute.
-- Clients are owned by an organization (never by a user directly). The record key
-- is the OAuth client_id string, so `client:⟨id⟩` and the client_id are the same value.
DEFINE TABLE client SCHEMAFULL
    PERMISSIONS NONE;

DEFINE FIELD id                ON client TYPE string ASSERT $value != NONE;
DEFINE FIELD name              ON client TYPE option<string>;  -- human-readable display name shown in first-party UI
DEFINE FIELD organization      ON client TYPE record<organization>;
DEFINE FIELD created_by        ON client TYPE option<record<user>>;  -- who created it (audit only, not ownership)
DEFINE FIELD secret_hash       ON client TYPE option<string>;
DEFINE FIELD redirect_uris     ON client TYPE array<string> DEFAULT [];
DEFINE FIELD scopes            ON client TYPE array<string> DEFAULT [];
DEFINE FIELD auto_grant_scopes ON client TYPE bool DEFAULT false;
DEFINE FIELD public            ON client TYPE bool DEFAULT false;

DEFINE INDEX client_id      ON client FIELDS id UNIQUE;
DEFINE INDEX idx_client_org ON client FIELDS organization;
