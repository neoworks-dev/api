-- ── Encrypted contact envelopes ───────────────────────────────────────────────
-- The server stores an opaque envelope per contact: ciphertext blob plus the
-- minimum plaintext needed to sync and authorize. Content (names, phones,
-- favorite/archived flags, the contact-to-contact graph) lives inside `blob`,
-- AES-256-GCM under a key derived from the space key; the AAD binds (contact id,
-- space, collection, key_epoch, schema_ver, base_seq, deleted) so ciphertext
-- cannot be spliced across rows, spaces, or epochs. `sig` is the author's
-- account-level Ed25519 signature so members cannot forge each other's rows.
--
-- Ids are client-chosen UUIDs: the AAD must bind the id before upload.
-- `seq` is assigned server-side from the owning space's counter in the same
-- transaction; UNIQUE (space, seq) doubles as the race backstop.
DEFINE TABLE contact SCHEMAFULL;
DEFINE FIELD space      ON contact TYPE record<space> READONLY;
DEFINE FIELD seq        ON contact TYPE int;
DEFINE FIELD base_seq   ON contact TYPE int;               -- client's OCC base at write time; part of the AAD
DEFINE FIELD key_epoch  ON contact TYPE int;
DEFINE FIELD schema_ver ON contact TYPE int DEFAULT 1;     -- openschema contacts schema revision
DEFINE FIELD deleted    ON contact TYPE bool DEFAULT false;
-- Set server-side when a tombstone lands; drives retention purge. Separate from
-- updated_at because that column is VALUE time::now() and cannot be pinned.
DEFINE FIELD deleted_at ON contact TYPE option<datetime>;
DEFINE FIELD blob       ON contact TYPE option<string>;    -- base64(12B nonce || AES-GCM ciphertext); NONE once tombstoned
DEFINE FIELD sig        ON contact TYPE option<string>;    -- base64 Ed25519(author sign key, blake2b(AAD || blob))
DEFINE FIELD author     ON contact TYPE record<user>;
-- Newest version of this contact. NONE only for a tombstone whose versions were
-- purged; every live row points at the version carrying its current content.
DEFINE FIELD version    ON contact TYPE option<record<contact_version>>;
DEFINE FIELD created_at ON contact TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD updated_at ON contact TYPE datetime VALUE time::now();

DEFINE INDEX idx_contact_space_seq   ON contact FIELDS space, seq UNIQUE;
DEFINE INDEX idx_contact_space_epoch ON contact FIELDS space, key_epoch;

-- ── Encrypted version history ─────────────────────────────────────────────────
-- Append-only. The client authors each version: it mints the version UUID, encodes
-- a ContactVersion payload carrying `parent_ids`, and encrypts and signs it under
-- its own AAD and its own derived key. Every accepted write lands one version; a
-- conflict merge lands two (the losing branch and the merge result).
--
-- The server never sees the lineage: `parent_ids` is inside `blob`, so it can
-- order versions by seq but cannot tell a branch point from a leaf. Ordering
-- within one seq is resolved on device from the decrypted parents.
DEFINE TABLE contact_version SCHEMAFULL;
DEFINE FIELD contact    ON contact_version TYPE record<contact> READONLY;
DEFINE FIELD space      ON contact_version TYPE record<space>   READONLY;
DEFINE FIELD seq        ON contact_version TYPE int             READONLY;
DEFINE FIELD base_seq   ON contact_version TYPE int             READONLY;
DEFINE FIELD key_epoch  ON contact_version TYPE int             READONLY;
DEFINE FIELD schema_ver ON contact_version TYPE int             READONLY;
DEFINE FIELD deleted    ON contact_version TYPE bool            READONLY;
DEFINE FIELD blob       ON contact_version TYPE option<string>  READONLY;
DEFINE FIELD sig        ON contact_version TYPE option<string>  READONLY;
DEFINE FIELD author     ON contact_version TYPE record<user>    READONLY;
DEFINE FIELD created_at ON contact_version TYPE datetime VALUE time::now() READONLY;

DEFINE INDEX idx_contact_version_contact ON contact_version FIELDS contact, seq;
