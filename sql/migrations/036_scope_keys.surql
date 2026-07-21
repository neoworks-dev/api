-- ── Per-scope public keys ──────────────────────────────────────────────────────
-- The scope-bound decryption pipeline derives a distinct X25519 keypair per
-- encryption scope from the AMK (apps/oauth/handlers/auth/static/scope-keys.js).
-- The Vault publishes each granted scope's PUBLIC key here so writers (the
-- account's other apps, or another user sharing in) can seal a DEK to the right
-- scope without ever holding a private key. Private keys are never stored — they
-- are re-derived from the AMK by the key-holder on each unlock.
DEFINE TABLE user_scope_key SCHEMAFULL;
DEFINE FIELD user       ON user_scope_key TYPE record<user>;
DEFINE FIELD scope      ON user_scope_key TYPE string;   -- encryption label, e.g. "photos"
DEFINE FIELD public_key ON user_scope_key TYPE string;   -- base64 X25519 public key
DEFINE FIELD created_at ON user_scope_key TYPE datetime DEFAULT time::now() READONLY;
DEFINE FIELD updated_at ON user_scope_key TYPE datetime VALUE time::now();

DEFINE INDEX idx_user_scope_key_unique ON user_scope_key FIELDS user, scope UNIQUE;

-- ── File encryption scope ─────────────────────────────────────────────────────
-- Which scope key a file object's DEK is sealed under. Absent ⇒ the legacy
-- account key (pre-migration objects). The tag lets the key-holder pick the right
-- keypair when unsealing on read.
DEFINE FIELD scope ON file         TYPE option<string>;
DEFINE FIELD scope ON file_version TYPE option<string> READONLY;
