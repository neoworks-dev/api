-- Hosting plan for an organization. Decouples where the org's client databases
-- live from its payment state (mollie_mandate_status stays payment-only):
--   free — the org's client databases share one SurrealDB instance, isolated by
--          the per-client namespace (client_{clientID}). No dedicated instance.
--   pro  — the org gets a dedicated / managed database (provisioned separately).
-- New orgs default to free; existing rows are backfilled below.
DEFINE FIELD plan ON organization TYPE string DEFAULT "free"
    ASSERT $value IN ["free", "pro"];

-- Backfill rows created before this field existed so reads never see NONE.
UPDATE organization SET plan = "free" WHERE plan = NONE;
