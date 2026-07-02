-- ── grant: a user's standing authorization of a client for a set of scopes ─────
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
DEFINE TABLE refresh_token SCHEMAFULL;
DEFINE FIELD user       ON refresh_token TYPE record<user>;
DEFINE FIELD client     ON refresh_token TYPE record<client>;
DEFINE FIELD scopes     ON refresh_token TYPE array<string>;
DEFINE FIELD expires_at ON refresh_token TYPE datetime;
DEFINE FIELD created_at ON refresh_token TYPE datetime DEFAULT time::now() READONLY;
DEFINE FIELD revoked    ON refresh_token TYPE bool DEFAULT false;
DEFINE FIELD used       ON refresh_token TYPE bool DEFAULT false;

DEFINE INDEX refresh_token_user_idx       ON refresh_token FIELDS user;
DEFINE INDEX refresh_token_client_idx     ON refresh_token FIELDS client;
DEFINE INDEX refresh_token_expires_at_idx ON refresh_token FIELDS expires_at;

-- ── scope_grant: a user-granted scope authorizing a client to access data ──────
-- Scope format: `organization?:entity:action`.
--   organization omitted  → entity refers to the user's personal data on Neoworks
--   organization present   → entity refers to data inside that organization's clients
-- The raw string is kept for OAuth tokens; parsed components are stored for lookup.
DEFINE TABLE scope_grant SCHEMAFULL;
DEFINE FIELD user          ON scope_grant TYPE record<user>   READONLY;
DEFINE FIELD client        ON scope_grant TYPE record<client> READONLY;
DEFINE FIELD raw           ON scope_grant TYPE string;                       -- e.g. "org_123:documents:write"
DEFINE FIELD organization  ON scope_grant TYPE option<record<organization>>; -- NONE ⇒ personal data on Neoworks
DEFINE FIELD entity        ON scope_grant TYPE string;                       -- e.g. "contacts", "documents"
DEFINE FIELD action        ON scope_grant TYPE string ASSERT $value IN ["read", "write"];
DEFINE FIELD enabled       ON scope_grant TYPE bool DEFAULT true;
DEFINE FIELD created_at    ON scope_grant TYPE datetime VALUE time::now() READONLY;
DEFINE FIELD updated_at    ON scope_grant TYPE datetime VALUE time::now();

DEFINE INDEX idx_scope_grant_lookup ON scope_grant FIELDS user, client, organization, entity, action;
DEFINE INDEX idx_scope_grant_user   ON scope_grant FIELDS user;
DEFINE INDEX idx_scope_grant_client ON scope_grant FIELDS client;
DEFINE INDEX idx_scope_grant_unique ON scope_grant FIELDS user, client, raw UNIQUE;

-- ── rate_limit: per-window request counters ───────────────────────────────────
DEFINE TABLE rate_limit SCHEMAFULL;
-- composite key built by the app: "<type>:<id>:<endpoint>", e.g. "ip:1.2.3.4:POST:/oauth/token"
DEFINE FIELD bucket     ON rate_limit TYPE string;
-- truncated timestamp for the current window (e.g. floored to the minute)
DEFINE FIELD window     ON rate_limit TYPE datetime;
DEFINE FIELD count      ON rate_limit TYPE int DEFAULT 0;
-- set to window + window_duration so stale rows can be purged
DEFINE FIELD expires_at ON rate_limit TYPE datetime;

-- (bucket, window) uniquely identifies one counter per window
DEFINE INDEX idx_rate_limit_bucket_window ON rate_limit FIELDS bucket, window UNIQUE;
-- used by background purge job to delete expired rows
DEFINE INDEX idx_rate_limit_expires       ON rate_limit FIELDS expires_at;

-- ── approval_request: cross-device sign-in / token-refresh approvals ──────────
-- Pending requests routed to a user's authenticator devices. Decided rows are
-- kept (not deleted) so they also feed the Home "Recent activity" feed.
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
