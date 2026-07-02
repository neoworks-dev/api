-- ── Account public key ────────────────────────────────────────────────────────
-- The X25519 public key derived (client-side, in the Vault) from the AMK. Senders
-- seal a media object's DEK to this key so the owner can later unseal it. The
-- private key is never stored — it is re-derived from the AMK on each unlock.
-- public_key_fingerprint is stored so out-of-band key verification can be added
-- later (the directory is currently trusted).
DEFINE FIELD public_key             ON user_key TYPE option<string>;
DEFINE FIELD public_key_fingerprint ON user_key TYPE option<string>;

-- ── Media DEK recipients ───────────────────────────────────────────────────────
-- Each media object is encrypted under a random per-object DEK (AES-GCM). The DEK
-- is sealed (crypto_box_seal) to one or more recipient public keys; `recipients`
-- holds those wrapped copies. The owner is always the first recipient. Sharing
-- appends another recipient; un-sharing removes one.
DEFINE FIELD recipients                  ON media TYPE array<object> DEFAULT [];
DEFINE FIELD recipients[*].key_id        ON media TYPE string;  -- recipient user id (bare)
DEFINE FIELD recipients[*].wrapped_dek   ON media TYPE string;  -- base64 crypto_box_seal(DEK, pubkey)

DEFINE FIELD recipients                  ON media_version TYPE array<object> DEFAULT [] READONLY;
DEFINE FIELD recipients[*].key_id        ON media_version TYPE string       READONLY;
DEFINE FIELD recipients[*].wrapped_dek   ON media_version TYPE string       READONLY;

-- ── Media share grants ─────────────────────────────────────────────────────────
-- Authorization layer, separate from the crypto: a grant lets `recipient` fetch
-- the encrypted chunks of `media` owned by `owner`. Decryption still requires the
-- recipient's sealed DEK wrapper (see media.recipients). Dropping a grant stops
-- future fetches; it does not protect data the recipient already downloaded.
DEFINE TABLE media_grant SCHEMAFULL;
DEFINE FIELD media      ON media_grant TYPE record<media> READONLY;
DEFINE FIELD owner      ON media_grant TYPE record<user>  READONLY;
DEFINE FIELD recipient  ON media_grant TYPE record<user>  READONLY;
DEFINE FIELD created_at ON media_grant TYPE datetime VALUE time::now() READONLY;

DEFINE INDEX idx_media_grant_unique    ON media_grant FIELDS media, recipient UNIQUE;
DEFINE INDEX idx_media_grant_recipient ON media_grant FIELDS recipient;
DEFINE INDEX idx_media_grant_media     ON media_grant FIELDS media;
