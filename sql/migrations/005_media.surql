-- ── derived_from: shared version-ancestry relation ────────────────────────────
-- Connects old_version -> derived_from -> new_version. IN and OUT are intentionally
-- untyped so it is shared across every versioned entity (media, contact, …).
DEFINE TABLE derived_from SCHEMAFULL TYPE RELATION;

-- ── chunk: content-addressed, per-user encrypted blob ─────────────────────────
-- Chunks are scoped to a user: encrypted chunks dedupe only within one user's
-- uploads (two users with the same plaintext produce different ciphertext → hashes).
DEFINE TABLE chunk SCHEMAFULL;
DEFINE FIELD user        ON chunk TYPE record<user> READONLY;
DEFINE FIELD hash        ON chunk TYPE string   READONLY; -- SHA-256 hex
DEFINE FIELD size        ON chunk TYPE int      READONLY; -- exact byte size
DEFINE FIELD storage_key ON chunk TYPE string   READONLY; -- path/key in object storage
-- counts array-slot references across media.chunks + media_version.chunks; when it
-- drops to 0 the chunk row and its object-storage blob are garbage collected
DEFINE FIELD ref_count   ON chunk TYPE int DEFAULT 0;
DEFINE FIELD created_at  ON chunk TYPE datetime VALUE time::now() READONLY;

DEFINE INDEX idx_chunk_user_hash ON chunk FIELDS user, hash UNIQUE;

-- ── media: current state (mirrors media_version for direct reads without joins) ──
DEFINE TABLE media SCHEMAFULL;
DEFINE FIELD user              ON media TYPE record<user>          READONLY;
DEFINE FIELD filename          ON media TYPE string;
DEFINE FIELD mime_type         ON media TYPE string;
DEFINE FIELD size              ON media TYPE int;                  -- sum of chunk sizes in bytes
DEFINE FIELD chunks            ON media TYPE array<record<chunk>>;
DEFINE FIELD version           ON media TYPE option<record<media_version>>;
-- provenance only: ownership stays with the user even when managed via a client
DEFINE FIELD managed_by_client ON media TYPE option<record<client>>;
DEFINE FIELD created_at        ON media TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD updated_at        ON media TYPE datetime VALUE time::now();

DEFINE INDEX idx_media_user       ON media FIELDS user;
DEFINE INDEX idx_media_mime_type  ON media FIELDS mime_type;
DEFINE INDEX idx_media_managed_by ON media FIELDS managed_by_client;

-- ── media_version: append-only history ────────────────────────────────────────
DEFINE TABLE media_version SCHEMAFULL;
DEFINE FIELD media_id   ON media_version TYPE record<media>        READONLY;
DEFINE FIELD user       ON media_version TYPE record<user>         READONLY;
DEFINE FIELD filename   ON media_version TYPE string               READONLY;
DEFINE FIELD mime_type  ON media_version TYPE string               READONLY;
DEFINE FIELD size       ON media_version TYPE int                  READONLY;
DEFINE FIELD chunks     ON media_version TYPE array<record<chunk>> READONLY;
DEFINE FIELD created_at ON media_version TYPE datetime VALUE time::now() READONLY;

DEFINE INDEX idx_media_version_media ON media_version FIELDS media_id;
DEFINE INDEX idx_media_version_user  ON media_version FIELDS user;
