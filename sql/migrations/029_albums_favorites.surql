-- ── Favorites ────────────────────────────────────────────────────────────────
-- A lightweight per-user "starred" marker on a file object. Not versioned and
-- not part of the file record itself — a row exists iff the user favorited the
-- file; deleting it un-favorites. The UNIQUE index makes (user, file) idempotent.
DEFINE TABLE file_favorite SCHEMAFULL;
DEFINE FIELD user       ON file_favorite TYPE record<user>  READONLY;
DEFINE FIELD file      ON file_favorite TYPE record<file> READONLY;
DEFINE FIELD created_at ON file_favorite TYPE datetime VALUE time::now() READONLY;

DEFINE INDEX idx_file_favorite_unique ON file_favorite FIELDS user, file UNIQUE;
DEFINE INDEX idx_file_favorite_user   ON file_favorite FIELDS user;
DEFINE INDEX idx_file_favorite_file  ON file_favorite FIELDS file;

-- ── Albums ───────────────────────────────────────────────────────────────────
-- A flat, user-owned, named collection of file. Not versioned. The cover and
-- member count are derived at query time from album_file (no denormalized fields
-- to keep in sync).
DEFINE TABLE album SCHEMAFULL;
DEFINE FIELD user       ON album TYPE record<user> READONLY;
DEFINE FIELD name       ON album TYPE string;
DEFINE FIELD created_at ON album TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD updated_at ON album TYPE datetime VALUE time::now();

DEFINE INDEX idx_album_user ON album FIELDS user;

-- ── Album membership ─────────────────────────────────────────────────────────
-- Edge linking a file object into an album. `user` is denormalized from the
-- album owner so membership queries scope by user without a join. UNIQUE makes
-- add idempotent; a file object may belong to many albums.
DEFINE TABLE album_file SCHEMAFULL;
DEFINE FIELD album      ON album_file TYPE record<album> READONLY;
DEFINE FIELD file      ON album_file TYPE record<file> READONLY;
DEFINE FIELD user       ON album_file TYPE record<user>  READONLY;
DEFINE FIELD created_at ON album_file TYPE datetime VALUE time::now() READONLY;

DEFINE INDEX idx_album_file_unique ON album_file FIELDS album, file UNIQUE;
DEFINE INDEX idx_album_file_album  ON album_file FIELDS album;
DEFINE INDEX idx_album_file_file  ON album_file FIELDS file;
DEFINE INDEX idx_album_file_user   ON album_file FIELDS user;
