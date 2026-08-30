-- ── Google account linking + calendar sync coordination ───────────────────────
-- Deliberate exception to the rule that this server stores no usable secret.
-- Everything else it holds is wrapped key material it cannot unwrap
-- (`user_scope_key`: "Private keys are never stored"). A Google refresh token is
-- different: it is a live bearer credential for a third party, and the server
-- holds it because a browser cannot obtain one — Google issues refresh tokens
-- only to a client that presents a client_secret, and a Web-application client
-- is the only client type whose redirect URIs can be a hosted origin.
--
-- What this buys, and what it costs:
--   * The server can mint Google access tokens for any device the user signs in
--     on, so linking is per account rather than per device.
--   * The server can therefore also read that user's Google calendar. The
--     mitigation is at rest (AES-GCM under INSTANCE_SECRET_KEY, sealed by
--     storage/database/google.go) and in policy, not in cryptography.
-- Event *content* still never reaches this server in the clear: the sync loop
-- runs inside the Vault, and the only per-event state stored here is an opaque
-- id pair and a content hash.

-- ── Linked Google account ─────────────────────────────────────────────────────
-- One per neoworks user. `refresh_token` and `access_token` are stored sealed;
-- the column type is string either way, since an unconfigured INSTANCE_SECRET_KEY
-- stores them verbatim (development only).
DEFINE TABLE google_account SCHEMAFULL;
DEFINE FIELD user          ON google_account TYPE record<user> READONLY;
-- Google's stable subject id. Survives an email change, so it — not `email` —
-- is what identifies the linked Google identity.
DEFINE FIELD google_sub    ON google_account TYPE string;
DEFINE FIELD email         ON google_account TYPE option<string>;
DEFINE FIELD refresh_token ON google_account TYPE string;
DEFINE FIELD access_token  ON google_account TYPE option<string>;
DEFINE FIELD expires_at    ON google_account TYPE option<datetime>;
DEFINE FIELD scopes        ON google_account TYPE array<string> DEFAULT [];
DEFINE FIELD linked_at     ON google_account TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD updated_at    ON google_account TYPE datetime VALUE time::now();

DEFINE INDEX idx_google_account_user ON google_account FIELDS user UNIQUE;

-- ── Calendar ↔ space link ─────────────────────────────────────────────────────
-- Which neoworks space mirrors which Google calendar, plus the pull cursor.
-- `access_role` is Google's, copied at link time: only owner/writer sync both
-- ways — pushing to a reader calendar 403s forever, so those are pulled only.
-- `sync_token` is Google's incremental cursor; a 410 clears it and forces a full
-- resync, mirroring the item store's purged-cursor path.
DEFINE TABLE google_calendar_link SCHEMAFULL;
DEFINE FIELD user                ON google_calendar_link TYPE record<user> READONLY;
DEFINE FIELD space               ON google_calendar_link TYPE record<space> READONLY;
DEFINE FIELD google_calendar_id  ON google_calendar_link TYPE string READONLY;
DEFINE FIELD access_role         ON google_calendar_link TYPE string DEFAULT 'reader'
    ASSERT $value IN ['owner', 'writer', 'reader', 'freeBusyReader'];
DEFINE FIELD sync_token          ON google_calendar_link TYPE option<string>;
DEFINE FIELD enabled             ON google_calendar_link TYPE bool DEFAULT true;
DEFINE FIELD created_at          ON google_calendar_link TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD updated_at          ON google_calendar_link TYPE datetime VALUE time::now();

DEFINE INDEX idx_google_calendar_link_unique ON google_calendar_link
    FIELDS user, google_calendar_id UNIQUE;
DEFINE INDEX idx_google_calendar_link_user ON google_calendar_link FIELDS user;

-- ── Event ↔ Google event link ─────────────────────────────────────────────────
-- The join between a jsCalendar `uid` and the Google event carrying it as its
-- `iCalUID`, plus `content_hash` — the guard that stops every device pushing the
-- same edit. A device pushes only when the row it holds hashes to something
-- other than what is recorded here, so "pending work" is derived from the
-- encrypted store rather than kept as a second outbox.
--
-- `google_calendar_id` is denormalized from the calendar link so event links can
-- be listed and dropped per calendar without a join over every uid the user owns.
DEFINE TABLE google_event_link SCHEMAFULL;
DEFINE FIELD user               ON google_event_link TYPE record<user> READONLY;
DEFINE FIELD uid                ON google_event_link TYPE string READONLY;
DEFINE FIELD google_calendar_id ON google_event_link TYPE string;
DEFINE FIELD google_event_id    ON google_event_link TYPE string;
DEFINE FIELD content_hash       ON google_event_link TYPE option<string>;
DEFINE FIELD pushed_at          ON google_event_link TYPE option<datetime>;
DEFINE FIELD created_at         ON google_event_link TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD updated_at         ON google_event_link TYPE datetime VALUE time::now();

DEFINE INDEX idx_google_event_link_unique ON google_event_link FIELDS user, uid UNIQUE;
DEFINE INDEX idx_google_event_link_calendar ON google_event_link
    FIELDS user, google_calendar_id;

-- ── Scope ─────────────────────────────────────────────────────────────────────
-- google:link gates every /google/* route on the oauth origin. Without it those
-- routes would be an open Google OAuth proxy for anyone holding any access token.
UPDATE client SET scopes += ["google:link"]
    WHERE id IN [client:⟨neoworks-calendar⟩, client:⟨neoworks.dev⟩];
