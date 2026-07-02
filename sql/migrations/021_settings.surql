-- Shared per-user settings, keyed by (client_id, user, key). Each client (OAuth
-- app) stores its own settings, but any client can read another client's settings
-- for the same user, so apps can reference each other's preferences. The value is
-- stored as a JSON string the client encodes/decodes.

DEFINE TABLE setting SCHEMAFULL;
DEFINE FIELD client_id  ON setting TYPE string;
DEFINE FIELD user       ON setting TYPE record<user> READONLY;
DEFINE FIELD key        ON setting TYPE string;
DEFINE FIELD value      ON setting TYPE string;
DEFINE FIELD created_at ON setting TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD updated_at ON setting TYPE datetime VALUE time::now();

-- One row per (user, client, key); upserts target it.
DEFINE INDEX idx_setting_unique ON setting FIELDS user, client_id, key UNIQUE;
DEFINE INDEX idx_setting_user   ON setting FIELDS user;
