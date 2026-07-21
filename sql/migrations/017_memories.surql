-- Memories: searchable embeddings for contextual recall (rambles, transcripts,
-- documents) alongside the structured data already in the database. A memory is
-- its own entity, NOT file — it may *reference* an encrypted file blob but never
-- inlines the bytes.
--
-- Privacy is decided by deployment, not per-query crypto. On a user-owned
-- (self-hosted) server the operator is the user, so content + embeddings are
-- stored plaintext and indexed. On the neoworks-hosted multi-tenant server,
-- indexing is opt-in per memory via `searchable`:
--   searchable = true  → `source_text` + chunk embeddings stored plaintext, indexed.
--   searchable = false → `source_text`/embeddings cleared, bytes kept in the
--                        encrypted `file` ref (encryption is client-side, via the
--                        Vault/AMK sandbox — the server never encrypts).
--
-- The embedding model is tiered by deployment (CPU self-host = Qwen3-Embedding-0.6b,
-- GPU hosted = Qwen3-Embedding-8b), both truncated to a common 1024-dim via
-- Matryoshka so the HNSW DIMENSION stays fixed. The producing model is stamped on
-- every chunk so a tier change can be detected and re-embedded (see embed_backfill).

-- ── memory: the source record ─────────────────────────────────────────────────
-- User-scoped with an optional organization, mirroring `asset` (migration 013).
DEFINE TABLE memory SCHEMAFULL;

DEFINE FIELD user         ON memory TYPE record<user> READONLY;
DEFINE FIELD organization ON memory TYPE option<record<organization>> READONLY;

DEFINE FIELD kind  ON memory TYPE string DEFAULT 'text'
    ASSERT $value IN ['text', 'image', 'audio', 'video', 'document'];
DEFINE FIELD title ON memory TYPE option<string>;

-- Raw source text when the memory is searchable; cleared (NONE) when not.
DEFINE FIELD source_text ON memory TYPE option<string>;

-- Reference into the encrypted file handler for non-searchable / binary bytes.
DEFINE FIELD file ON memory TYPE option<record<file>>;

-- Opt-in toggle. On self-host the Go layer forces this true; on hosted it is the
-- user's choice and gates whether chunks carry plaintext content + vectors.
DEFINE FIELD searchable ON memory TYPE bool DEFAULT false;

DEFINE FIELD deleted    ON memory TYPE bool DEFAULT false;
DEFINE FIELD created_at ON memory TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD updated_at ON memory TYPE datetime VALUE time::now();

DEFINE INDEX idx_memory_user    ON memory FIELDS user;
DEFINE INDEX idx_memory_deleted ON memory FIELDS user, deleted;

-- ── memory_chunk: embeddable pieces of a memory ───────────────────────────────
-- One memory fans out to many chunks (token windows for text). `user` is
-- denormalized for scoped vector search. NOTE: named `memory_chunk`, not `chunk` —
-- `chunk` is the encrypted-file block table from migration 005.
DEFINE TABLE memory_chunk SCHEMAFULL;

DEFINE FIELD memory ON memory_chunk TYPE record<memory> READONLY;
DEFINE FIELD user   ON memory_chunk TYPE record<user>   READONLY;

DEFINE FIELD idx      ON memory_chunk TYPE int;                  -- order within the memory
DEFINE FIELD modality ON memory_chunk TYPE string DEFAULT 'text'
    ASSERT $value IN ['text', 'image', 'audio', 'video', 'document'];

-- The embeddable text (kept so a retry needs no re-chunk).
DEFINE FIELD content ON memory_chunk TYPE option<string>;

-- Where this chunk came from inside the source: {start, end} char offsets.
DEFINE FIELD span ON memory_chunk TYPE option<object> FLEXIBLE;

-- The 1024-dim Matryoshka-truncated, L2-normalized embedding (NONE until embedded).
DEFINE FIELD embedding ON memory_chunk TYPE option<array<float>>;

-- Provenance + lifecycle so the backfill job can find pending/stale chunks.
DEFINE FIELD model       ON memory_chunk TYPE option<string>;   -- e.g. 'qwen3-embedding:0.6b'
DEFINE FIELD dim         ON memory_chunk TYPE option<int>;
DEFINE FIELD embed_ver   ON memory_chunk TYPE int DEFAULT 1;
DEFINE FIELD status      ON memory_chunk TYPE string DEFAULT 'pending'
    ASSERT $value IN ['pending', 'ready', 'failed'];
DEFINE FIELD retry_count ON memory_chunk TYPE int DEFAULT 0;

DEFINE FIELD created_at ON memory_chunk TYPE datetime VALUE $before OR time::now() READONLY;

DEFINE INDEX idx_memory_chunk_memory ON memory_chunk FIELDS memory;
DEFINE INDEX idx_memory_chunk_user   ON memory_chunk FIELDS user;
DEFINE INDEX idx_memory_chunk_status ON memory_chunk FIELDS status;

-- Approximate-nearest-neighbour index for vector search. Cosine distance on f32;
-- DIMENSION is fixed at 1024 — both model tiers truncate to it via Matryoshka.
-- The <|K|> operator filters non-vector predicates (user, status) AFTER the ANN
-- walk, so the store over-fetches and filters, or brute-forces for small sets.
DEFINE INDEX idx_memory_chunk_hnsw ON memory_chunk
    FIELDS embedding
    HNSW DIMENSION 1024 DIST COSINE TYPE F32 EFC 150 M 12;

-- Lexical half of hybrid search; reuses the english analyzer from migration 007.
DEFINE INDEX idx_memory_chunk_fts ON memory_chunk
    FIELDS content
    FULLTEXT ANALYZER contact_text BM25 HIGHLIGHTS;
