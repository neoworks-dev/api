-- Sortable "effective date": the photo's EXIF capture time when present, else its
-- upload time. ORDER BY needs a plain field (it rejects expressions like
-- "capture_date OR created_at"), so the library sorts by this column to keep
-- EXIF-less uploads ordered by recency instead of sinking below every dated photo.
DEFINE FIELD effective_date ON media TYPE datetime VALUE (capture_date OR created_at);

-- Backfill existing rows (the VALUE clause recomputes on this write).
UPDATE media SET effective_date = (capture_date OR created_at);
