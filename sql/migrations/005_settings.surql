-- ── setting: per-user key/value settings, keyed by (client_id, user, key) ────
-- Each client stores its own settings; any client may read another client's
-- settings for the same user. The value is a JSON string the client encodes.
DEFINE TABLE setting SCHEMAFULL;
DEFINE FIELD client_id  ON setting TYPE string;
DEFINE FIELD user       ON setting TYPE record<user> READONLY;
DEFINE FIELD key        ON setting TYPE string;
DEFINE FIELD value      ON setting TYPE string;
DEFINE FIELD created_at ON setting TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD updated_at ON setting TYPE datetime VALUE time::now();

DEFINE INDEX idx_setting_unique ON setting FIELDS user, client_id, key UNIQUE;
DEFINE INDEX idx_setting_user   ON setting FIELDS user;
