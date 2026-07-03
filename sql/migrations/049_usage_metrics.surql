-- Time-series usage samples for the per-database usage dashboard. The metering
-- ticker writes one row per active org instance (compute + memory + storage) and
-- one row per active client database (query activity) each sample window.
--
-- CPU/memory/storage are instance-level: an org's client databases share one
-- SurrealDB container, so those figures reflect the whole instance. Query stats
-- are per-database, measured by the API as it brokers each query.
--
-- All statements use IF NOT EXISTS so a partially-applied run can be re-run safely.

-- ── Instance-level sample (CPU / memory / storage) ────────────────────────────
DEFINE TABLE IF NOT EXISTS instance_metric SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS instance      ON instance_metric TYPE record<org_instance>  READONLY;
DEFINE FIELD IF NOT EXISTS organization  ON instance_metric TYPE record<organization>  READONLY;
DEFINE FIELD IF NOT EXISTS cpu_percent   ON instance_metric TYPE float                 READONLY;
DEFINE FIELD IF NOT EXISTS mem_bytes     ON instance_metric TYPE int                   READONLY;
DEFINE FIELD IF NOT EXISTS mem_percent   ON instance_metric TYPE float                 READONLY;
DEFINE FIELD IF NOT EXISTS storage_bytes ON instance_metric TYPE int                   READONLY;
DEFINE FIELD IF NOT EXISTS sampled_at    ON instance_metric TYPE datetime              READONLY;
DEFINE FIELD IF NOT EXISTS created_at    ON instance_metric TYPE datetime VALUE time::now() READONLY;

DEFINE INDEX IF NOT EXISTS idx_instance_metric_inst_time ON instance_metric FIELDS instance, sampled_at;
DEFINE INDEX IF NOT EXISTS idx_instance_metric_org_time  ON instance_metric FIELDS organization, sampled_at;

-- ── Per-database query sample (latency / throughput / connections) ────────────
DEFINE TABLE IF NOT EXISTS database_metric SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS database           ON database_metric TYPE record<client_database> READONLY;
DEFINE FIELD IF NOT EXISTS instance           ON database_metric TYPE option<record<org_instance>> READONLY;
DEFINE FIELD IF NOT EXISTS query_count        ON database_metric TYPE int   READONLY;
DEFINE FIELD IF NOT EXISTS avg_latency_ms     ON database_metric TYPE float READONLY;
DEFINE FIELD IF NOT EXISTS active_connections ON database_metric TYPE int   READONLY;
DEFINE FIELD IF NOT EXISTS sampled_at         ON database_metric TYPE datetime READONLY;
DEFINE FIELD IF NOT EXISTS created_at         ON database_metric TYPE datetime VALUE time::now() READONLY;

DEFINE INDEX IF NOT EXISTS idx_database_metric_db_time ON database_metric FIELDS database, sampled_at;
