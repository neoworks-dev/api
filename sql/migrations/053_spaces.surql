-- ── Spaces ────────────────────────────────────────────────────────────────────
-- A space is the unit of sharing and sync for end-to-end encrypted entities.
-- Every encrypted row belongs to exactly one space; a space holds exactly one
-- collection. Members hold the symmetric space key sealed to their
-- per-collection scope public key (crypto_box_seal); the server only ever stores
-- wrapped copies. `seq` is the per-space sync counter: every accepted item write
-- increments it inside the push transaction, so the space row is the
-- serialization point and (space, seq) is the pull cursor.
--
-- Space ids are uuid-typed, because an item's id embeds its space's
-- (`item:[space_uuid, item_uuid]`, see 054) and a string there would defeat the
-- key ordering that shape exists for.
DEFINE TABLE space SCHEMAFULL;
DEFINE FIELD owner         ON space TYPE record<user> READONLY;
-- One collection per space: a space holding two would hand out both with one
-- key. This list is the full set of end-to-end encrypted collections; anything
-- the server must read (files) keeps its own table.
DEFINE FIELD collection    ON space TYPE string READONLY
    ASSERT $value IN ['contacts', 'calendar', 'memories'];
DEFINE FIELD kind          ON space TYPE string READONLY
    ASSERT $value IN ['personal', 'shared', 'adhoc'];
-- Client-encrypted display label; the server cannot read space names.
DEFINE FIELD name_enc      ON space TYPE option<string>;
DEFINE FIELD key_epoch     ON space TYPE int DEFAULT 1;
DEFINE FIELD seq           ON space TYPE int DEFAULT 0;
-- Tombstones with seq <= purge_horizon have been deleted; cursors below it must
-- full-resync (pull returns 410).
DEFINE FIELD purge_horizon ON space TYPE int DEFAULT 0;
DEFINE FIELD created_at    ON space TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD updated_at    ON space TYPE datetime VALUE time::now();

DEFINE INDEX idx_space_owner ON space FIELDS owner;

-- ── Space membership ──────────────────────────────────────────────────────────
-- Authorization + key distribution in one row (file_grant precedent, plus the
-- wrapped key material). `wrapped_keys` carries one sealed copy of the space key
-- per epoch the member may read. `signature` is the inviter's Ed25519 signature
-- over the wrap context; on accept the member re-signs and pins client-side
-- (`accept_signature`), so neither the server nor the inviter can silently swap
-- key material afterwards.
DEFINE TABLE space_member SCHEMAFULL;
DEFINE FIELD space      ON space_member TYPE record<space> READONLY;
DEFINE FIELD user       ON space_member TYPE record<user>  READONLY;
DEFINE FIELD role       ON space_member TYPE string DEFAULT 'reader'
    ASSERT $value IN ['owner', 'writer', 'reader'];
DEFINE FIELD status     ON space_member TYPE string DEFAULT 'invited'
    ASSERT $value IN ['invited', 'active'];
DEFINE FIELD added_by   ON space_member TYPE record<user> READONLY;
DEFINE FIELD wrapped_keys                ON space_member TYPE array<object> DEFAULT [];
DEFINE FIELD wrapped_keys[*].epoch       ON space_member TYPE int;
DEFINE FIELD wrapped_keys[*].wrapped_key ON space_member TYPE string; -- base64 crypto_box_seal(space_key, member scope pubkey)
DEFINE FIELD wrapped_keys[*].signature   ON space_member TYPE string; -- base64 Ed25519 by inviter over wrap context
DEFINE FIELD accept_signature ON space_member TYPE option<string>;    -- member's re-signature (pin), set on accept
DEFINE FIELD created_at ON space_member TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD updated_at ON space_member TYPE datetime VALUE time::now();

DEFINE INDEX idx_space_member_unique ON space_member FIELDS space, user UNIQUE;
DEFINE INDEX idx_space_member_user   ON space_member FIELDS user;
