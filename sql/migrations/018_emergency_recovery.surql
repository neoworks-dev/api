-- ── Social recovery: split the account's social key across trusted guardians ──
-- The owner generates a 32-byte social key, wraps the AMK with it
-- (social_wrapped_amk), Shamir-splits the key into N shares (threshold K), and
-- seals each guardian's share to that guardian's device public keys. The server
-- only ever stores ciphertext — never a plaintext share or the AMK.

-- Extend user_key with the social-recovery wrap + threshold metadata.
DEFINE FIELD social_wrapped_amk ON user_key TYPE option<string>;
DEFINE FIELD social_threshold   ON user_key TYPE option<int>;
DEFINE FIELD social_total       ON user_key TYPE option<int>;

-- ── emergency_contact: a guardian designated by the owner ────────────────────
DEFINE TABLE emergency_contact SCHEMAFULL;
DEFINE FIELD owner       ON emergency_contact TYPE record<user> READONLY;
DEFINE FIELD guardian    ON emergency_contact TYPE record<user>;
DEFINE FIELD email       ON emergency_contact TYPE string;
DEFINE FIELD label       ON emergency_contact TYPE option<string>;
DEFINE FIELD share_index ON emergency_contact TYPE int;
DEFINE FIELD created_at   ON emergency_contact TYPE datetime VALUE time::now() READONLY;
DEFINE INDEX idx_emergency_contact_owner ON emergency_contact COLUMNS owner;

-- ── recovery_share: a guardian's sealed share, one row per guardian device ───
DEFINE TABLE recovery_share SCHEMAFULL;
DEFINE FIELD owner             ON recovery_share TYPE record<user> READONLY;
DEFINE FIELD guardian          ON recovery_share TYPE record<user>;
DEFINE FIELD share_index       ON recovery_share TYPE int;
DEFINE FIELD device_public_key ON recovery_share TYPE string;
DEFINE FIELD sealed_share      ON recovery_share TYPE string;
DEFINE FIELD created_at         ON recovery_share TYPE datetime VALUE time::now() READONLY;
DEFINE INDEX idx_recovery_share_owner    ON recovery_share COLUMNS owner;
DEFINE INDEX idx_recovery_share_guardian ON recovery_share COLUMNS guardian;

-- ── recovery_session: an in-progress account recovery on a new device ────────
DEFINE TABLE recovery_session SCHEMAFULL;
DEFINE FIELD owner                 ON recovery_session TYPE record<user> READONLY;
DEFINE FIELD recovering_public_key ON recovery_session TYPE string       READONLY;
DEFINE FIELD threshold             ON recovery_session TYPE int;
DEFINE FIELD status                ON recovery_session TYPE string DEFAULT 'pending';
DEFINE FIELD created_at             ON recovery_session TYPE datetime VALUE time::now() READONLY;
DEFINE FIELD expires_at             ON recovery_session TYPE datetime;
DEFINE INDEX idx_recovery_session_owner ON recovery_session COLUMNS owner;

-- ── recovery_session_share: shares submitted by guardians for a session ──────
-- Each is re-sealed by the guardian to the session's recovering_public_key, so
-- only the new device can open them.
DEFINE TABLE recovery_session_share SCHEMAFULL;
DEFINE FIELD session      ON recovery_session_share TYPE record<recovery_session> READONLY;
DEFINE FIELD guardian     ON recovery_session_share TYPE record<user>;
DEFINE FIELD share_index  ON recovery_session_share TYPE int;
DEFINE FIELD sealed_share ON recovery_session_share TYPE string;
DEFINE FIELD created_at     ON recovery_session_share TYPE datetime VALUE time::now() READONLY;
DEFINE INDEX uniq_recovery_session_share ON recovery_session_share COLUMNS session, guardian UNIQUE;
