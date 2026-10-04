-- ── client: an application that signs users in ───────────────────────────────
-- The record key is the OAuth client_id string. Clients are seed data (see 007);
-- there is no self-registration.
DEFINE TABLE client SCHEMAFULL
    PERMISSIONS NONE;

DEFINE FIELD id                ON client TYPE string ASSERT $value != NONE;
DEFINE FIELD name              ON client TYPE option<string>;
DEFINE FIELD secret_hash       ON client TYPE option<string>;
DEFINE FIELD redirect_uris     ON client TYPE array<string> DEFAULT [];
DEFINE FIELD scopes            ON client TYPE array<string> DEFAULT [];
DEFINE FIELD auto_grant_scopes ON client TYPE bool DEFAULT false;
DEFINE FIELD public            ON client TYPE bool DEFAULT false;

DEFINE INDEX client_id ON client FIELDS id UNIQUE;

-- ── grant: a user's standing authorization of a client for a set of scopes ───
DEFINE TABLE grant SCHEMAFULL;
DEFINE FIELD user       ON grant TYPE record<user>;
DEFINE FIELD client     ON grant TYPE record<client>;
DEFINE FIELD scopes     ON grant TYPE array<string>;
DEFINE FIELD enabled    ON grant TYPE bool DEFAULT true;
DEFINE FIELD created_at ON grant TYPE datetime DEFAULT time::now() READONLY;
DEFINE FIELD updated_at ON grant TYPE datetime DEFAULT time::now();

DEFINE INDEX grant_user_idx               ON grant FIELDS user;
DEFINE INDEX grant_client_idx             ON grant FIELDS client;
DEFINE INDEX grant_user_client_unique_idx ON grant FIELDS user, client UNIQUE;

-- ── refresh_token: issued OAuth refresh tokens ────────────────────────────────
-- `install` binds the token to an app installation; NONE for the account vault.
DEFINE TABLE refresh_token SCHEMAFULL;
DEFINE FIELD user       ON refresh_token TYPE record<user>;
DEFINE FIELD client     ON refresh_token TYPE record<client>;
DEFINE FIELD install    ON refresh_token TYPE option<record<install>>;
DEFINE FIELD scopes     ON refresh_token TYPE array<string>;
DEFINE FIELD expires_at ON refresh_token TYPE datetime;
DEFINE FIELD created_at ON refresh_token TYPE datetime DEFAULT time::now() READONLY;
DEFINE FIELD revoked    ON refresh_token TYPE bool DEFAULT false;
DEFINE FIELD used       ON refresh_token TYPE bool DEFAULT false;

DEFINE INDEX refresh_token_user_idx       ON refresh_token FIELDS user;
DEFINE INDEX refresh_token_client_idx     ON refresh_token FIELDS client;
DEFINE INDEX refresh_token_install_idx    ON refresh_token FIELDS install;
DEFINE INDEX refresh_token_expires_at_idx ON refresh_token FIELDS expires_at;

-- ── approval_request: cross-device sign-in / token-refresh approvals ──────────
-- Pending requests routed to a user's authenticator devices. Decided rows are
-- kept so they also feed the "Recent activity" feed.
DEFINE TABLE approval_request SCHEMAFULL;
DEFINE FIELD user                   ON approval_request TYPE record<user> READONLY;
DEFINE FIELD type                   ON approval_request TYPE string
    ASSERT $value IN ["signin", "token_refresh"]                         READONLY;
DEFINE FIELD status                 ON approval_request TYPE string
    ASSERT $value IN ["pending", "approved", "denied", "expired"]        DEFAULT "pending";
DEFINE FIELD client                 ON approval_request TYPE string       READONLY;
DEFINE FIELD scopes                 ON approval_request TYPE array<string> DEFAULT [];
DEFINE FIELD requesting_label       ON approval_request TYPE option<string>;
DEFINE FIELD requesting_user_agent  ON approval_request TYPE option<string>;
DEFINE FIELD ip                     ON approval_request TYPE option<string>;
DEFINE FIELD location               ON approval_request TYPE option<string>;
DEFINE FIELD login_challenge        ON approval_request TYPE option<string>;
DEFINE FIELD created_at             ON approval_request TYPE datetime VALUE time::now() READONLY;
DEFINE FIELD decided_at             ON approval_request TYPE option<datetime>;
DEFINE FIELD expires_at             ON approval_request TYPE datetime     READONLY;

DEFINE INDEX idx_approval_user         ON approval_request COLUMNS user;
DEFINE INDEX idx_approval_user_status  ON approval_request COLUMNS user, status;
DEFINE INDEX idx_approval_challenge    ON approval_request COLUMNS login_challenge;

-- ── push_token: per-user FCM/APNs registration tokens ─────────────────────────
DEFINE TABLE push_token SCHEMAFULL;
DEFINE FIELD user       ON push_token TYPE record<user>          READONLY;
DEFINE FIELD device     ON push_token TYPE option<record<device>>;
DEFINE FIELD platform   ON push_token TYPE string ASSERT $value IN ["fcm", "apns"];
DEFINE FIELD token      ON push_token TYPE string;
DEFINE FIELD created_at ON push_token TYPE datetime VALUE time::now() READONLY;
DEFINE FIELD updated_at ON push_token TYPE datetime VALUE time::now();

DEFINE INDEX idx_push_token_token ON push_token COLUMNS token UNIQUE;
DEFINE INDEX idx_push_token_user  ON push_token COLUMNS user;
