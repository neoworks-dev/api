-- Media search: full-text over filenames + a per-media embedding table for
-- vector (visual/text) search. Embeddings are computed client-side (the server
-- never sees decrypted media) and stored as queryable plaintext vectors so the
-- HNSW/BM25 arms can run server-side. Mirrors the memory_chunk conventions
-- (017_memories.surql); reuses the contact_text analyzer (007).

-- BM25 over filenames, backing MediaFilter.filename.search (@@) and the lexical
-- arm of mediaSearch.
DEFINE INDEX idx_media_filename_fts ON media
    FIELDS filename FULLTEXT ANALYZER contact_text BM25 HIGHLIGHTS;

DEFINE TABLE media_embedding SCHEMAFULL;

DEFINE FIELD media   ON media_embedding TYPE record<media> READONLY;
DEFINE FIELD user    ON media_embedding TYPE record<user>  READONLY;

-- One media may have several embeddings of different modalities (the image
-- itself, OCR text, future audio/video frames). 'image' is the default.
DEFINE FIELD modality ON media_embedding TYPE string DEFAULT 'image'
    ASSERT $value IN ['image', 'ocr', 'thumbnail', 'metadata', 'text', 'audio', 'video'];

-- Embeddable text (OCR / alt-text) for the BM25 arm; NONE for pure-vector rows.
DEFINE FIELD content ON media_embedding TYPE option<string>;

-- The vector (NONE until the client fills it). 768-dim nomic-embed-vision-v1.5,
-- the same space as nomic-embed-text query embeddings.
DEFINE FIELD embedding ON media_embedding TYPE option<array<float>>;

-- Provenance + lifecycle (mirrors memory_chunk).
DEFINE FIELD model       ON media_embedding TYPE option<string>;
DEFINE FIELD dim         ON media_embedding TYPE option<int>;
DEFINE FIELD embed_ver   ON media_embedding TYPE int DEFAULT 1;
DEFINE FIELD status      ON media_embedding TYPE string DEFAULT 'pending'
    ASSERT $value IN ['pending', 'ready', 'failed'];
DEFINE FIELD retry_count ON media_embedding TYPE int DEFAULT 0;

DEFINE FIELD created_at ON media_embedding TYPE datetime VALUE $before OR time::now() READONLY;

DEFINE INDEX idx_media_embedding_media  ON media_embedding FIELDS media;
DEFINE INDEX idx_media_embedding_user   ON media_embedding FIELDS user;
DEFINE INDEX idx_media_embedding_status ON media_embedding FIELDS status;
DEFINE INDEX idx_media_embedding_hnsw   ON media_embedding
    FIELDS embedding HNSW DIMENSION 768 DIST COSINE TYPE F32 EFC 150 M 12;
DEFINE INDEX idx_media_embedding_fts    ON media_embedding
    FIELDS content FULLTEXT ANALYZER contact_text BM25 HIGHLIGHTS;
