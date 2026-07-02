-- ── Favorites ────────────────────────────────────────────────────────────────
-- A lightweight per-user "starred" marker on a media object. Not versioned and
-- not part of the media record itself — a row exists iff the user favorited the
-- media; deleting it un-favorites. The UNIQUE index makes (user, media) idempotent.
DEFINE TABLE media_favorite SCHEMAFULL;
DEFINE FIELD user       ON media_favorite TYPE record<user>  READONLY;
DEFINE FIELD media      ON media_favorite TYPE record<media> READONLY;
DEFINE FIELD created_at ON media_favorite TYPE datetime VALUE time::now() READONLY;

DEFINE INDEX idx_media_favorite_unique ON media_favorite FIELDS user, media UNIQUE;
DEFINE INDEX idx_media_favorite_user   ON media_favorite FIELDS user;
DEFINE INDEX idx_media_favorite_media  ON media_favorite FIELDS media;

-- ── Albums ───────────────────────────────────────────────────────────────────
-- A flat, user-owned, named collection of media. Not versioned. The cover and
-- member count are derived at query time from album_media (no denormalized fields
-- to keep in sync).
DEFINE TABLE album SCHEMAFULL;
DEFINE FIELD user       ON album TYPE record<user> READONLY;
DEFINE FIELD name       ON album TYPE string;
DEFINE FIELD created_at ON album TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD updated_at ON album TYPE datetime VALUE time::now();

DEFINE INDEX idx_album_user ON album FIELDS user;

-- ── Album membership ─────────────────────────────────────────────────────────
-- Edge linking a media object into an album. `user` is denormalized from the
-- album owner so membership queries scope by user without a join. UNIQUE makes
-- add idempotent; a media object may belong to many albums.
DEFINE TABLE album_media SCHEMAFULL;
DEFINE FIELD album      ON album_media TYPE record<album> READONLY;
DEFINE FIELD media      ON album_media TYPE record<media> READONLY;
DEFINE FIELD user       ON album_media TYPE record<user>  READONLY;
DEFINE FIELD created_at ON album_media TYPE datetime VALUE time::now() READONLY;

DEFINE INDEX idx_album_media_unique ON album_media FIELDS album, media UNIQUE;
DEFINE INDEX idx_album_media_album  ON album_media FIELDS album;
DEFINE INDEX idx_album_media_media  ON album_media FIELDS media;
DEFINE INDEX idx_album_media_user   ON album_media FIELDS user;
