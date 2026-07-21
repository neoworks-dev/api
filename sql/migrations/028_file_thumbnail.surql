-- Thumbnails + file purpose. A thumbnail is its own (encrypted) file object,
-- linked from the original via `thumbnail`, so the grid can load a small image
-- and only fetch the full one on demand. `purpose` marks derived file (e.g.
-- 'thumbnail') so they are excluded from the main library listing and skipped by
-- the embedding queue.

DEFINE FIELD thumbnail ON file TYPE option<record<file>>;
DEFINE FIELD purpose   ON file TYPE option<string>;

DEFINE INDEX idx_file_purpose ON file FIELDS purpose;
