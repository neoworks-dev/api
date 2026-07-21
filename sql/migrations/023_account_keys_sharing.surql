-- ── Account public key ────────────────────────────────────────────────────────
-- The X25519 public key derived (client-side, in the Vault) from the AMK. Senders
-- seal a file object's DEK to this key so the owner can later unseal it. The
-- private key is never stored — it is re-derived from the AMK on each unlock.
-- public_key_fingerprint is stored so out-of-band key verification can be added
-- later (the directory is currently trusted).
DEFINE FIELD public_key             ON user_key TYPE option<string>;
DEFINE FIELD public_key_fingerprint ON user_key TYPE option<string>;

-- ── File DEK recipients ───────────────────────────────────────────────────────
-- Each file object is encrypted under a random per-object DEK (AES-GCM). The DEK
-- is sealed (crypto_box_seal) to one or more recipient public keys; `recipients`
-- holds those wrapped copies. The owner is always the first recipient. Sharing
-- appends another recipient; un-sharing removes one.
DEFINE FIELD recipients                  ON file TYPE array<object> DEFAULT [];
DEFINE FIELD recipients[*].key_id        ON file TYPE string;  -- recipient user id (bare)
DEFINE FIELD recipients[*].wrapped_dek   ON file TYPE string;  -- base64 crypto_box_seal(DEK, pubkey)

DEFINE FIELD recipients                  ON file_version TYPE array<object> DEFAULT [] READONLY;
DEFINE FIELD recipients[*].key_id        ON file_version TYPE string       READONLY;
DEFINE FIELD recipients[*].wrapped_dek   ON file_version TYPE string       READONLY;

-- ── File share grants ─────────────────────────────────────────────────────────
-- Authorization layer, separate from the crypto: a grant lets `recipient` fetch
-- the encrypted chunks of `file` owned by `owner`. Decryption still requires the
-- recipient's sealed DEK wrapper (see file.recipients). Dropping a grant stops
-- future fetches; it does not protect data the recipient already downloaded.
DEFINE TABLE file_grant SCHEMAFULL;
DEFINE FIELD file      ON file_grant TYPE record<file> READONLY;
DEFINE FIELD owner      ON file_grant TYPE record<user>  READONLY;
DEFINE FIELD recipient  ON file_grant TYPE record<user>  READONLY;
DEFINE FIELD created_at ON file_grant TYPE datetime VALUE time::now() READONLY;

DEFINE INDEX idx_file_grant_unique    ON file_grant FIELDS file, recipient UNIQUE;
DEFINE INDEX idx_file_grant_recipient ON file_grant FIELDS recipient;
DEFINE INDEX idx_file_grant_file     ON file_grant FIELDS file;
