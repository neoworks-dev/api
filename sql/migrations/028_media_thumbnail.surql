-- Thumbnails + media purpose. A thumbnail is its own (encrypted) media object,
-- linked from the original via `thumbnail`, so the grid can load a small image
-- and only fetch the full one on demand. `purpose` marks derived media (e.g.
-- 'thumbnail') so they are excluded from the main library listing and skipped by
-- the embedding queue.

DEFINE FIELD thumbnail ON media TYPE option<record<media>>;
DEFINE FIELD purpose   ON media TYPE option<string>;

DEFINE INDEX idx_media_purpose ON media FIELDS purpose;
