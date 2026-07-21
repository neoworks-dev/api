-- ── derived_from: shared version-ancestry relation ────────────────────────────
-- Connects old_version -> derived_from -> new_version. IN and OUT are intentionally
-- untyped so it is shared across every versioned entity (file, contact, …).
DEFINE TABLE derived_from SCHEMAFULL TYPE RELATION;

-- ── chunk: content-addressed, per-user encrypted blob ─────────────────────────
-- Chunks are scoped to a user: encrypted chunks dedupe only within one user's
-- uploads (two users with the same plaintext produce different ciphertext → hashes).
DEFINE TABLE chunk SCHEMAFULL;
DEFINE FIELD user        ON chunk TYPE record<user> READONLY;
DEFINE FIELD hash        ON chunk TYPE string   READONLY; -- SHA-256 hex
DEFINE FIELD size        ON chunk TYPE int      READONLY; -- exact byte size
DEFINE FIELD storage_key ON chunk TYPE string   READONLY; -- path/key in object storage
-- counts array-slot references across file.chunks + file_version.chunks; when it
-- drops to 0 the chunk row and its object-storage blob are garbage collected
DEFINE FIELD ref_count   ON chunk TYPE int DEFAULT 0;
DEFINE FIELD created_at  ON chunk TYPE datetime VALUE time::now() READONLY;

DEFINE INDEX idx_chunk_user_hash ON chunk FIELDS user, hash UNIQUE;

-- ── file: current state (mirrors file_version for direct reads without joins) ──
DEFINE TABLE file SCHEMAFULL;
DEFINE FIELD user              ON file TYPE record<user>          READONLY;
DEFINE FIELD filename          ON file TYPE string;
DEFINE FIELD mime_type         ON file TYPE string;
DEFINE FIELD size              ON file TYPE int;                  -- sum of chunk sizes in bytes
DEFINE FIELD chunks            ON file TYPE array<record<chunk>>;
DEFINE FIELD version           ON file TYPE option<record<file_version>>;
-- provenance only: ownership stays with the user even when managed via a client
DEFINE FIELD managed_by_client ON file TYPE option<record<client>>;
DEFINE FIELD created_at        ON file TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD updated_at        ON file TYPE datetime VALUE time::now();

DEFINE INDEX idx_file_user       ON file FIELDS user;
DEFINE INDEX idx_file_mime_type  ON file FIELDS mime_type;
DEFINE INDEX idx_file_managed_by ON file FIELDS managed_by_client;

-- ── file_version: append-only history ────────────────────────────────────────
DEFINE TABLE file_version SCHEMAFULL;
DEFINE FIELD file_id   ON file_version TYPE record<file>        READONLY;
DEFINE FIELD user       ON file_version TYPE record<user>         READONLY;
DEFINE FIELD filename   ON file_version TYPE string               READONLY;
DEFINE FIELD mime_type  ON file_version TYPE string               READONLY;
DEFINE FIELD size       ON file_version TYPE int                  READONLY;
DEFINE FIELD chunks     ON file_version TYPE array<record<chunk>> READONLY;
DEFINE FIELD created_at ON file_version TYPE datetime VALUE time::now() READONLY;

DEFINE INDEX idx_file_version_file ON file_version FIELDS file_id;
DEFINE INDEX idx_file_version_user  ON file_version FIELDS user;
