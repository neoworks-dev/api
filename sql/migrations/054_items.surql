-- ── Encrypted envelopes, one table for every collection ───────────────────────
-- The server stores an opaque envelope per item: ciphertext blob plus the
-- minimum plaintext needed to sync and authorize. Content lives inside `blob`,
-- AES-256-GCM under a key derived from the space key; the AAD binds (item id,
-- space, collection, key_epoch, schema_ver, base_seq, deleted) so ciphertext
-- cannot be spliced across rows, spaces, collections, or epochs. `sig` is the
-- author's account-level Ed25519 signature so members cannot forge each other's
-- rows.
--
-- There is deliberately NO `collection` column. 053 fixes a space to exactly one
-- collection (members hold the space key sealed to their per-collection scope
-- key), so an item's collection is a property of its space. A column here would
-- denormalize the space row, and no client query names a collection anyway — it
-- names a space, and the space decides. The AAD still binds `collection`, so
-- ciphertext cannot be replayed into another collection's space.
--
-- Ids are composite and uuid-typed: `item:[space_uuid, item_uuid]`. RocksDB
-- stores rows in key order, so every row of a space is contiguous; the sync
-- page, the space range read and the epoch worklist are 3.5-9x faster than the
-- flat shape once the working set exceeds RAM, and the keyspace compresses
-- better because adjacent keys share their prefix. Item uuids stay client-chosen
-- — the AAD must bind the id before upload.
--
-- `seq` is assigned server-side from the owning space's counter in the same
-- transaction; UNIQUE (space, seq) doubles as the race backstop.
DEFINE TABLE item SCHEMAFULL;
DEFINE FIELD space      ON item TYPE record<space> READONLY;
DEFINE FIELD seq        ON item TYPE int;
DEFINE FIELD base_seq   ON item TYPE int;               -- client's OCC base at write time; part of the AAD
DEFINE FIELD key_epoch  ON item TYPE int;
DEFINE FIELD schema_ver ON item TYPE int DEFAULT 1;     -- openschema revision of the collection's schema
DEFINE FIELD deleted    ON item TYPE bool DEFAULT false;
-- Set server-side when a tombstone lands; drives retention purge. Separate from
-- updated_at because that column is VALUE time::now() and cannot be pinned.
DEFINE FIELD deleted_at ON item TYPE option<datetime>;
DEFINE FIELD blob       ON item TYPE option<string>;    -- base64(12B nonce || AES-GCM ciphertext); NONE once tombstoned
DEFINE FIELD sig        ON item TYPE option<string>;    -- base64 Ed25519(author sign key, blake2b(AAD || blob))
DEFINE FIELD author     ON item TYPE record<user>;
-- Newest version of this item. NONE only for a tombstone whose versions were
-- purged; every live row points at the version carrying its current content.
DEFINE FIELD version    ON item TYPE option<record<item_version>>;
DEFINE FIELD created_at ON item TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD updated_at ON item TYPE datetime VALUE time::now();

DEFINE INDEX idx_item_space_seq   ON item FIELDS space, seq UNIQUE;
DEFINE INDEX idx_item_space_epoch ON item FIELDS space, key_epoch;
-- The purge job scans tombstones past the retention window across all spaces.
-- Without this it is a full table scan of every collection at once.
DEFINE INDEX idx_item_deleted_at  ON item FIELDS deleted_at;

-- ── Encrypted version history ─────────────────────────────────────────────────
-- Append-only, and its own table rather than a discriminator on `item`: a head
-- and the version(s) written with it carry the SAME `seq`, so one table could
-- not keep (space, seq) UNIQUE, and every sync poll would have to filter history
-- rows out of its own hot index.
--
-- The client authors each version: it mints the version UUID, encodes a payload
-- carrying `parent_ids`, and encrypts and signs it under its own AAD and its own
-- derived key. Every accepted write lands one version; a conflict merge lands
-- two (the losing branch and the merge result).
--
-- The server never sees the lineage: `parent_ids` is inside `blob`, so it can
-- order versions by seq but cannot tell a branch point from a leaf. Ordering
-- within one seq is resolved on device from the decrypted parents.
--
-- `item_id` is a scalar uuid, NOT a record link. SurrealDB 3.1.5 never uses an
-- index on a link whose target has an array id — `WHERE item = $ref` plans as a
-- TableScan over the whole history table, which is the largest table here. The
-- scalar column plans as an IndexScan. The cost is losing `.item` traversal and
-- referential typing; the parent is still reachable as
-- item:[space_uuid, item_id]. Predicates must bind it first
-- (`LET $iid = <uuid>$item`) — a cast inside the predicate defeats the index.
DEFINE TABLE item_version SCHEMAFULL;
DEFINE FIELD item_id    ON item_version TYPE uuid           READONLY;
DEFINE FIELD space      ON item_version TYPE record<space>  READONLY;
DEFINE FIELD seq        ON item_version TYPE int            READONLY;
DEFINE FIELD base_seq   ON item_version TYPE int            READONLY;
DEFINE FIELD key_epoch  ON item_version TYPE int            READONLY;
DEFINE FIELD schema_ver ON item_version TYPE int            READONLY;
DEFINE FIELD deleted    ON item_version TYPE bool           READONLY;
DEFINE FIELD blob       ON item_version TYPE option<string> READONLY;
DEFINE FIELD sig        ON item_version TYPE option<string> READONLY;
DEFINE FIELD author     ON item_version TYPE record<user>   READONLY;
DEFINE FIELD created_at ON item_version TYPE datetime VALUE time::now() READONLY;

DEFINE INDEX idx_item_version_item ON item_version FIELDS item_id, seq;
