-- ── user: a Neoworks account holder ───────────────────────────────────────────
DEFINE TABLE user SCHEMAFULL;
DEFINE FIELD first_name        ON user TYPE string;
DEFINE FIELD last_name         ON user TYPE string;
DEFINE FIELD email             ON user TYPE string
    ASSERT string::is_email($value);
DEFINE FIELD password_hash     ON user TYPE string;
-- running total of object-storage bytes for this user; storage pricing is
-- pass-through (no quotas), this is purely for billing/usage display
DEFINE FIELD storage_used_bytes ON user TYPE int DEFAULT 0;
DEFINE FIELD created_at         ON user TYPE datetime DEFAULT time::now() READONLY;

DEFINE INDEX user_email_unique ON user FIELDS email UNIQUE;

-- ── user_key: per-user encrypted AMK wrappers ─────────────────────────────────
DEFINE TABLE user_key SCHEMAFULL;
DEFINE FIELD user                 ON user_key TYPE record<user>         READONLY;
DEFINE FIELD recovery_wrapped_amk ON user_key TYPE string;
DEFINE FIELD password_wrapped_amk ON user_key TYPE option<string>;
DEFINE FIELD argon2_salt          ON user_key TYPE string;
DEFINE FIELD argon2_time          ON user_key TYPE int DEFAULT 3;
DEFINE FIELD argon2_memory        ON user_key TYPE int DEFAULT 65536;
DEFINE FIELD argon2_threads       ON user_key TYPE int DEFAULT 4;
DEFINE FIELD argon2_keylen        ON user_key TYPE int DEFAULT 32;
DEFINE FIELD created_at           ON user_key TYPE datetime VALUE time::now() READONLY;
DEFINE FIELD updated_at           ON user_key TYPE datetime VALUE time::now();
DEFINE INDEX idx_user_key_user    ON user_key COLUMNS user UNIQUE;

-- ── device: per-device public key + wrapped AMK ───────────────────────────────
DEFINE TABLE device SCHEMAFULL;
DEFINE FIELD user            ON device TYPE record<user>         READONLY;
DEFINE FIELD name            ON device TYPE option<string>;
DEFINE FIELD public_key      ON device TYPE string               READONLY;
DEFINE FIELD wrapped_amk     ON device TYPE string;
DEFINE FIELD created_at      ON device TYPE datetime VALUE time::now() READONLY;
DEFINE FIELD last_seen_at    ON device TYPE datetime VALUE time::now();
DEFINE INDEX idx_device_user ON device COLUMNS user;
