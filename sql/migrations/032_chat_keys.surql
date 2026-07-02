-- ── Chat device identity ──────────────────────────────────────────────────────
-- Each device is its own ratchet endpoint (Signal Sesame). It publishes two long-
-- term public keys, both derived in the Vault from blake2b(AMK || devicePubKey):
--   identity_key  — X25519, the DH half used in X3DH and the Double Ratchet.
--   signing_key   — Ed25519, signs the device's signed prekey.
-- Privates never leave the Vault. These are added to the existing device table.
DEFINE FIELD identity_key ON device TYPE option<string>;
DEFINE FIELD signing_key  ON device TYPE option<string>;

-- ── Signed prekey ──────────────────────────────────────────────────────────────
-- One current signed prekey per device (rotated periodically). public_key is an
-- X25519 key; signature is Ed25519(signing_key, public_key) so a sender can verify
-- the prekey really belongs to the device identity before running X3DH.
DEFINE TABLE chat_signed_prekey SCHEMAFULL;
DEFINE FIELD device     ON chat_signed_prekey TYPE record<device> READONLY;
DEFINE FIELD key_id     ON chat_signed_prekey TYPE int            READONLY;
DEFINE FIELD public_key ON chat_signed_prekey TYPE string         READONLY;
DEFINE FIELD signature  ON chat_signed_prekey TYPE string         READONLY;
DEFINE FIELD created_at ON chat_signed_prekey TYPE datetime VALUE time::now() READONLY;
DEFINE INDEX idx_chat_spk_device ON chat_signed_prekey FIELDS device;

-- ── One-time prekeys ───────────────────────────────────────────────────────────
-- A per-device pool of X25519 public keys, each consumed (popped) exactly once when
-- a sender fetches a bundle. Consumption is an atomic DELETE-RETURN in a transaction
-- so a key is never handed to two senders. When the pool empties, X3DH proceeds
-- without the optional one-time prekey (standard fallback, slightly reduced FS).
DEFINE TABLE chat_onetime_prekey SCHEMAFULL;
DEFINE FIELD device     ON chat_onetime_prekey TYPE record<device> READONLY;
DEFINE FIELD key_id     ON chat_onetime_prekey TYPE int            READONLY;
DEFINE FIELD public_key ON chat_onetime_prekey TYPE string         READONLY;
DEFINE FIELD created_at ON chat_onetime_prekey TYPE datetime VALUE time::now() READONLY;
DEFINE INDEX idx_chat_otpk_device ON chat_onetime_prekey FIELDS device;
