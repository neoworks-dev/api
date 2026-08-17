-- File search: full-text over filenames + a per-file embedding table for
-- vector (visual/text) search. Embeddings are computed client-side (the server
-- never sees decrypted file) and stored as queryable plaintext vectors so the
-- HNSW/BM25 arms can run server-side. Reuses the contact_text analyzer (007).
--
-- Files are the one collection that stays server-visible metadata: you fetch
-- specific files on demand, you do not sync every byte of every file down on
-- reconnect, so a searchable index earns its keep here in a way it cannot for
-- the E2EE collections in `item` (054).

-- BM25 over filenames, backing FileFilter.filename.search (@@) and the lexical
-- arm of fileSearch.
DEFINE INDEX idx_file_filename_fts ON file
    FIELDS filename FULLTEXT ANALYZER contact_text BM25 HIGHLIGHTS;

DEFINE TABLE file_embedding SCHEMAFULL;

DEFINE FIELD file   ON file_embedding TYPE record<file> READONLY;
DEFINE FIELD user    ON file_embedding TYPE record<user>  READONLY;

-- One file may have several embeddings of different modalities (the image
-- itself, OCR text, future audio/video frames). 'image' is the default.
DEFINE FIELD modality ON file_embedding TYPE string DEFAULT 'image'
    ASSERT $value IN ['image', 'ocr', 'thumbnail', 'metadata', 'text', 'audio', 'video'];

-- Embeddable text (OCR / alt-text) for the BM25 arm; NONE for pure-vector rows.
DEFINE FIELD content ON file_embedding TYPE option<string>;

-- The vector (NONE until the client fills it). 768-dim nomic-embed-vision-v1.5,
-- the same space as nomic-embed-text query embeddings.
DEFINE FIELD embedding ON file_embedding TYPE option<array<float>>;

-- Provenance + lifecycle.
DEFINE FIELD model       ON file_embedding TYPE option<string>;
DEFINE FIELD dim         ON file_embedding TYPE option<int>;
DEFINE FIELD embed_ver   ON file_embedding TYPE int DEFAULT 1;
DEFINE FIELD status      ON file_embedding TYPE string DEFAULT 'pending'
    ASSERT $value IN ['pending', 'ready', 'failed'];
DEFINE FIELD retry_count ON file_embedding TYPE int DEFAULT 0;

DEFINE FIELD created_at ON file_embedding TYPE datetime VALUE $before OR time::now() READONLY;

DEFINE INDEX idx_file_embedding_file  ON file_embedding FIELDS file;
DEFINE INDEX idx_file_embedding_user   ON file_embedding FIELDS user;
DEFINE INDEX idx_file_embedding_status ON file_embedding FIELDS status;
DEFINE INDEX idx_file_embedding_hnsw   ON file_embedding
    FIELDS embedding HNSW DIMENSION 768 DIST COSINE TYPE F32 EFC 150 M 12;
DEFINE INDEX idx_file_embedding_fts    ON file_embedding
    FIELDS content FULLTEXT ANALYZER contact_text BM25 HIGHLIGHTS;
