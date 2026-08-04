-- ── Encrypted contact envelopes ───────────────────────────────────────────────
-- The E2EE replacement for the plaintext `contact` tables. The server stores an
-- opaque envelope per contact: ciphertext blob + the minimum plaintext needed to
-- sync and authorize. Content (names, phones, favorite/archived flags, the
-- contact-to-contact graph) lives inside `blob`, AES-256-GCM under a key derived
-- from the space key; the AAD binds (item id, space, collection, key_epoch,
-- schema_ver, base_seq, deleted) so ciphertext cannot be spliced across rows,
-- spaces, or epochs. `sig` is the author's account-level Ed25519 signature so
-- members cannot forge each other's rows.
--
-- Ids are client-chosen UUIDs: the AAD must bind the id before upload.
-- `seq` is assigned server-side from the owning space's counter in the same
-- transaction; UNIQUE (space, seq) doubles as the race backstop.
DEFINE TABLE contact_item SCHEMAFULL;
DEFINE FIELD space      ON contact_item TYPE record<space> READONLY;
DEFINE FIELD seq        ON contact_item TYPE int;
DEFINE FIELD base_seq   ON contact_item TYPE int;               -- client's OCC base at write time; part of the AAD
DEFINE FIELD key_epoch  ON contact_item TYPE int;
DEFINE FIELD schema_ver ON contact_item TYPE int DEFAULT 1;     -- openschema contacts schema revision
DEFINE FIELD deleted    ON contact_item TYPE bool DEFAULT false;
-- Set server-side when a tombstone lands; drives retention purge. Separate from
-- updated_at because that column is VALUE time::now() and cannot be pinned.
DEFINE FIELD deleted_at ON contact_item TYPE option<datetime>;
DEFINE FIELD blob       ON contact_item TYPE option<string>;    -- base64(12B nonce || AES-GCM ciphertext); NONE once tombstoned
DEFINE FIELD sig        ON contact_item TYPE option<string>;    -- base64 Ed25519(author sign key, blake2b(AAD || blob))
DEFINE FIELD author     ON contact_item TYPE record<user>;
DEFINE FIELD created_at ON contact_item TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD updated_at ON contact_item TYPE datetime VALUE time::now();

DEFINE INDEX idx_contact_item_space_seq   ON contact_item FIELDS space, seq UNIQUE;
DEFINE INDEX idx_contact_item_space_epoch ON contact_item FIELDS space, key_epoch;

-- ── Encrypted version history ─────────────────────────────────────────────────
-- Append-only: before each update the pre-update row is copied here verbatim in
-- the push transaction. Rows are ciphertext the server cannot read; history is
-- decrypted on device. Lineage is linear per item, ordered by seq.
DEFINE TABLE contact_item_version SCHEMAFULL;
DEFINE FIELD item       ON contact_item_version TYPE record<contact_item> READONLY;
DEFINE FIELD space      ON contact_item_version TYPE record<space>        READONLY;
DEFINE FIELD seq        ON contact_item_version TYPE int                  READONLY;
DEFINE FIELD base_seq   ON contact_item_version TYPE int                  READONLY;
DEFINE FIELD key_epoch  ON contact_item_version TYPE int                  READONLY;
DEFINE FIELD schema_ver ON contact_item_version TYPE int                  READONLY;
DEFINE FIELD deleted    ON contact_item_version TYPE bool                 READONLY;
DEFINE FIELD blob       ON contact_item_version TYPE option<string>       READONLY;
DEFINE FIELD sig        ON contact_item_version TYPE option<string>       READONLY;
DEFINE FIELD author     ON contact_item_version TYPE record<user>         READONLY;
DEFINE FIELD item_created_at ON contact_item_version TYPE datetime        READONLY;
DEFINE FIELD created_at ON contact_item_version TYPE datetime VALUE time::now() READONLY;

DEFINE INDEX idx_contact_item_version_item ON contact_item_version FIELDS item, seq;
