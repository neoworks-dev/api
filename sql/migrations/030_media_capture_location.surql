-- Capture metadata extracted from uploaded photos (EXIF). Stored UNENCRYPTED on
-- the media row so it stays queryable/sortable — unlike the image bytes, which are
-- E2E encrypted. `capture_date` is the original capture time (EXIF DateTimeOriginal),
-- `location` the GPS point {lat, lng}, and `exif` the full parsed tag set.
DEFINE FIELD capture_date ON media TYPE option<datetime>;
DEFINE FIELD location     ON media TYPE option<object> FLEXIBLE;  -- {lat, lng}
DEFINE FIELD exif         ON media TYPE option<object> FLEXIBLE;  -- full parsed EXIF
