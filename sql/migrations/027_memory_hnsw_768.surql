-- Step 2 of the Nomic standardization (see 026): recreate the memory_chunk HNSW
-- index at 768 dimensions. Runs after 026 has committed the cleared vectors, so
-- the index builds over empty embeddings. The backfill worker then refills them
-- with nomic-embed-text-v1.5 once the model server is reachable.

DEFINE INDEX idx_memory_chunk_hnsw ON memory_chunk
    FIELDS embedding HNSW DIMENSION 768 DIST COSINE TYPE F32 EFC 150 M 12;
