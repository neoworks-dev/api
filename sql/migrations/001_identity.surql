-- ── user: a Neoworks account holder ───────────────────────────────────────────
-- The record id is the client-generated userId (lowercase UUIDv4), created on the
-- device at signup so it can be bound into AAD before the first upload.
DEFINE TABLE user SCHEMAFULL;
DEFINE FIELD email          ON user TYPE string
    ASSERT string::is_email($value);
-- bcrypt(base64url(authKey)); the password itself never reaches the server
DEFINE FIELD auth_hash      ON user TYPE string;
DEFINE FIELD escrow_enabled ON user TYPE bool DEFAULT false;
DEFINE FIELD first_name     ON user TYPE option<string>;
DEFINE FIELD last_name      ON user TYPE option<string>;
DEFINE FIELD created_at     ON user TYPE datetime DEFAULT time::now() READONLY;

DEFINE INDEX user_email_unique ON user FIELDS email UNIQUE;

-- ── key_bundle: the account's wrapped key material, one row per user ──────────
-- Opaque to the server. `version` starts at 1 and increases by one on every
-- rotation; a rotation swaps the whole row and is rejected unless it carries the
-- next version.
DEFINE TABLE key_bundle SCHEMAFULL;
DEFINE FIELD user             ON key_bundle TYPE record<user> READONLY;
DEFINE FIELD version          ON key_bundle TYPE int;
DEFINE FIELD pwhash_salt      ON key_bundle TYPE string;
DEFINE FIELD pwhash_ops       ON key_bundle TYPE int;
DEFINE FIELD pwhash_mem       ON key_bundle TYPE int;
DEFINE FIELD amk_password     ON key_bundle TYPE string;
DEFINE FIELD amk_recovery     ON key_bundle TYPE string;
DEFINE FIELD identity_private ON key_bundle TYPE string;
DEFINE FIELD enc_pub          ON key_bundle TYPE string;
DEFINE FIELD sign_pub         ON key_bundle TYPE string;
DEFINE FIELD self_sig         ON key_bundle TYPE string;
-- The identity before an unfinished full rotation, wrapped under the current
-- AMK; cleared once every key is rewrapped to the new identity.
DEFINE FIELD previous_identity_private ON key_bundle TYPE option<string>;
DEFINE FIELD previous_enc_pub          ON key_bundle TYPE option<string>;
DEFINE FIELD previous_sign_pub         ON key_bundle TYPE option<string>;
DEFINE FIELD updated_at       ON key_bundle TYPE datetime VALUE time::now();

DEFINE INDEX idx_key_bundle_user ON key_bundle FIELDS user UNIQUE;

-- ── device: a browser, authenticator or app the user signed in on ─────────────
-- The device's own AMK wrap never reaches the server.
DEFINE TABLE device SCHEMAFULL;
DEFINE FIELD user         ON device TYPE record<user> READONLY;
DEFINE FIELD name         ON device TYPE option<string>;
DEFINE FIELD kind         ON device TYPE string
    ASSERT $value IN ["browser", "authenticator", "app"];
DEFINE FIELD created_at   ON device TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD last_seen_at ON device TYPE datetime VALUE time::now();
DEFINE FIELD revoked_at   ON device TYPE option<datetime>;

DEFINE INDEX idx_device_user ON device FIELDS user;

-- ── install: one app installation, with its own keypairs ─────────────────────
-- The record id is the client-generated installId.
DEFINE TABLE install SCHEMAFULL;
DEFINE FIELD user       ON install TYPE record<user>   READONLY;
DEFINE FIELD client     ON install TYPE record<client> READONLY;
DEFINE FIELD enc_pub    ON install TYPE string         READONLY;
DEFINE FIELD sign_pub   ON install TYPE string         READONLY;
DEFINE FIELD name       ON install TYPE option<string>;
DEFINE FIELD created_at ON install TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD revoked_at ON install TYPE option<datetime>;

DEFINE INDEX idx_install_user ON install FIELDS user;

-- ── certificate: the user's delegation certificate for an install ────────────
-- `bytes` and `signature` are stored and served verbatim. The record id is the
-- certId. A certificate renewed by an authenticator names the identity-signed
-- certificate it extends and the renewal certificate that signed it.
DEFINE TABLE certificate SCHEMAFULL;
DEFINE FIELD user       ON certificate TYPE record<user>    READONLY;
DEFINE FIELD install    ON certificate TYPE record<install> READONLY;
DEFINE FIELD bytes      ON certificate TYPE string          READONLY;
DEFINE FIELD signature  ON certificate TYPE string          READONLY;
DEFINE FIELD origin_cert_id  ON certificate TYPE option<string> READONLY;
DEFINE FIELD renewal_cert_id ON certificate TYPE option<string> READONLY;
DEFINE FIELD created_at ON certificate TYPE datetime VALUE $before OR time::now() READONLY;

DEFINE INDEX idx_certificate_install ON certificate FIELDS install;

-- ── renewal_certificate: lets one authenticator device extend certificates ───
-- Signed by the user's identity key at enrollment. The record id is the
-- renewalCertId. Revoking the device revokes it.
DEFINE TABLE renewal_certificate SCHEMAFULL;
DEFINE FIELD user       ON renewal_certificate TYPE record<user>   READONLY;
DEFINE FIELD device     ON renewal_certificate TYPE record<device> READONLY;
DEFINE FIELD bytes      ON renewal_certificate TYPE string         READONLY;
DEFINE FIELD signature  ON renewal_certificate TYPE string         READONLY;
DEFINE FIELD expires_at ON renewal_certificate TYPE datetime       READONLY;
DEFINE FIELD created_at ON renewal_certificate TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD revoked_at ON renewal_certificate TYPE option<datetime>;

DEFINE INDEX idx_renewal_certificate_device ON renewal_certificate FIELDS device;
