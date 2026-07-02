-- Standardize the memory embedding space on Nomic (nomic-embed-text-v1.5, 768-dim)
-- so memories and media share one vector space. The HNSW index is fixed at its
-- creation dimension, so it must be recreated at 768 (done in 027).
--
-- Step 1 (this migration): drop the 1024-dim index and clear the stale vectors,
-- requeueing every chunk. Redefining the index must happen in a SEPARATE migration
-- (027) because each migration runs in its own transaction — the index build only
-- sees rows committed before it, so the vectors must be cleared and committed first.
-- Content is retained, so vectors are fully recomputable by the backfill worker.

REMOVE INDEX IF EXISTS idx_memory_chunk_hnsw ON memory_chunk;

UPDATE memory_chunk SET embedding = NONE, status = 'pending', retry_count = 0;
