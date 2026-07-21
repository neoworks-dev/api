-- Usage-billing event tables. Shared fields across all of them:
--   billed_to            — the billed party; either a user (personal usage) or an organization (client usage)
--   source_client        — the client that generated org usage, if any; NONE for personal user usage
--   units / size_bytes   — quantity being billed
--   unit_price           — price per unit locked in at event time
--   currency             — ISO 4217 code locked in at event time (e.g. "USD", "EUR")
--   status               — pending: not yet invoiced; invoiced: included in an invoice; void: cancelled
--   invoice_id           — set when the row is included in an invoice
--   ref                  — causal record (e.g. the file_version that triggered the event)
--   occurred_at          — when the billable activity happened
--   created_at           — when the row was inserted
--
-- Billing identities are fully separate: org usage bills the organization (never the
-- owner's personal account); personal usage bills the user. Routing happens in the
-- metering code: client/org usage → billed_to = client.organization, source_client = client.

-- ── Storage (open interval per stored object) ─────────────────────────────────
DEFINE TABLE billing_storage_period SCHEMAFULL;
DEFINE FIELD billed_to     ON billing_storage_period TYPE record<user | organization> READONLY;
DEFINE FIELD source_client ON billing_storage_period TYPE option<record<client>>      READONLY;
DEFINE FIELD tier          ON billing_storage_period TYPE string                      READONLY
    ASSERT $value IN ["hot", "cold", "archive"];
DEFINE FIELD size_bytes    ON billing_storage_period TYPE decimal                     READONLY;
DEFINE FIELD unit_price    ON billing_storage_period TYPE decimal                     READONLY;
DEFINE FIELD currency      ON billing_storage_period TYPE string                      READONLY;
DEFINE FIELD status        ON billing_storage_period TYPE string DEFAULT "pending"
    ASSERT $value IN ["pending", "invoiced", "void"];
DEFINE FIELD invoice_id    ON billing_storage_period TYPE option<string>;
DEFINE FIELD ref           ON billing_storage_period TYPE option<record>              READONLY;
-- open interval while data is stored; end_time is set when the data is deleted or replaced
-- GB-months = (size_bytes / 1_073_741_824) * (end_time - start_time).seconds / 2_629_800
DEFINE FIELD start_time    ON billing_storage_period TYPE datetime                    READONLY;
DEFINE FIELD end_time      ON billing_storage_period TYPE option<datetime>;
DEFINE FIELD created_at    ON billing_storage_period TYPE datetime VALUE time::now()  READONLY;

DEFINE INDEX idx_billing_storage_billed_time ON billing_storage_period FIELDS billed_to, start_time;
DEFINE INDEX idx_billing_storage_source      ON billing_storage_period FIELDS source_client;
DEFINE INDEX idx_billing_storage_open        ON billing_storage_period FIELDS end_time;
DEFINE INDEX idx_billing_storage_status      ON billing_storage_period FIELDS status;
DEFINE INDEX idx_billing_storage_invoice     ON billing_storage_period FIELDS invoice_id;

-- ── Compute (seconds of compute) ──────────────────────────────────────────────
DEFINE TABLE billing_compute_event SCHEMAFULL;
DEFINE FIELD billed_to     ON billing_compute_event TYPE record<user | organization> READONLY;
DEFINE FIELD source_client ON billing_compute_event TYPE option<record<client>>      READONLY;
DEFINE FIELD units         ON billing_compute_event TYPE decimal                     READONLY; -- seconds of compute
DEFINE FIELD unit_price    ON billing_compute_event TYPE decimal                     READONLY;
DEFINE FIELD currency      ON billing_compute_event TYPE string                      READONLY;
DEFINE FIELD status        ON billing_compute_event TYPE string DEFAULT "pending"
    ASSERT $value IN ["pending", "invoiced", "void"];
DEFINE FIELD invoice_id    ON billing_compute_event TYPE option<string>;
DEFINE FIELD ref           ON billing_compute_event TYPE option<record>              READONLY;
DEFINE FIELD occurred_at   ON billing_compute_event TYPE datetime                    READONLY;
DEFINE FIELD created_at    ON billing_compute_event TYPE datetime VALUE time::now()  READONLY;

DEFINE INDEX idx_billing_compute_billed_time ON billing_compute_event FIELDS billed_to, occurred_at;
DEFINE INDEX idx_billing_compute_source      ON billing_compute_event FIELDS source_client;
DEFINE INDEX idx_billing_compute_status      ON billing_compute_event FIELDS status;
DEFINE INDEX idx_billing_compute_invoice     ON billing_compute_event FIELDS invoice_id;

-- ── API calls (number of calls) ───────────────────────────────────────────────
DEFINE TABLE billing_api_event SCHEMAFULL;
DEFINE FIELD billed_to     ON billing_api_event TYPE record<user | organization> READONLY;
DEFINE FIELD source_client ON billing_api_event TYPE option<record<client>>      READONLY;
DEFINE FIELD units         ON billing_api_event TYPE decimal                     READONLY; -- number of calls
DEFINE FIELD unit_price    ON billing_api_event TYPE decimal                     READONLY;
DEFINE FIELD currency      ON billing_api_event TYPE string                      READONLY;
DEFINE FIELD status        ON billing_api_event TYPE string DEFAULT "pending"
    ASSERT $value IN ["pending", "invoiced", "void"];
DEFINE FIELD invoice_id    ON billing_api_event TYPE option<string>;
DEFINE FIELD ref           ON billing_api_event TYPE option<record>              READONLY;
DEFINE FIELD occurred_at   ON billing_api_event TYPE datetime                    READONLY;
DEFINE FIELD created_at    ON billing_api_event TYPE datetime VALUE time::now()  READONLY;

DEFINE INDEX idx_billing_api_billed_time ON billing_api_event FIELDS billed_to, occurred_at;
DEFINE INDEX idx_billing_api_source      ON billing_api_event FIELDS source_client;
DEFINE INDEX idx_billing_api_status      ON billing_api_event FIELDS status;
DEFINE INDEX idx_billing_api_invoice     ON billing_api_event FIELDS invoice_id;

-- ── Provisioning (e.g. database provisioning) ─────────────────────────────────
DEFINE TABLE billing_provisioning_event SCHEMAFULL;
DEFINE FIELD billed_to     ON billing_provisioning_event TYPE record<user | organization> READONLY;
DEFINE FIELD source_client ON billing_provisioning_event TYPE option<record<client>>      READONLY;
DEFINE FIELD resource      ON billing_provisioning_event TYPE string                      READONLY; -- e.g. "database"
DEFINE FIELD units         ON billing_provisioning_event TYPE decimal                     READONLY;
DEFINE FIELD unit_price    ON billing_provisioning_event TYPE decimal                     READONLY;
DEFINE FIELD currency      ON billing_provisioning_event TYPE string                      READONLY;
DEFINE FIELD status        ON billing_provisioning_event TYPE string DEFAULT "pending"
    ASSERT $value IN ["pending", "invoiced", "void"];
DEFINE FIELD invoice_id    ON billing_provisioning_event TYPE option<string>;
DEFINE FIELD ref           ON billing_provisioning_event TYPE option<record>              READONLY;
DEFINE FIELD occurred_at   ON billing_provisioning_event TYPE datetime                    READONLY;
DEFINE FIELD created_at    ON billing_provisioning_event TYPE datetime VALUE time::now()  READONLY;

DEFINE INDEX idx_billing_prov_billed_time ON billing_provisioning_event FIELDS billed_to, occurred_at;
DEFINE INDEX idx_billing_prov_source      ON billing_provisioning_event FIELDS source_client;
DEFINE INDEX idx_billing_prov_status      ON billing_provisioning_event FIELDS status;
DEFINE INDEX idx_billing_prov_invoice     ON billing_provisioning_event FIELDS invoice_id;
