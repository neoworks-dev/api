-- An organization's client databases live on a dedicated SurrealDB instance,
-- provisioned lazily the first time one of its clients creates a database. A
-- dedicated instance gives each org a hard compute + security boundary (SurrealDB
-- namespaces share one runtime, so a heavy tenant query can starve others) and a
-- clean per-instance unit to meter and bill. Orgs with no database have no row.
DEFINE TABLE org_instance SCHEMAFULL;
DEFINE FIELD organization  ON org_instance TYPE record<organization> READONLY;
-- ws:// admin endpoint the API dials to reach this org's instance as root.
DEFINE FIELD endpoint      ON org_instance TYPE string;
DEFINE FIELD status        ON org_instance TYPE string DEFAULT "provisioning"
    ASSERT $value IN ["provisioning", "active", "suspended", "failed"];
-- Opaque provisioner handle addressing the instance's workload on its substrate.
DEFINE FIELD handle        ON org_instance TYPE string;
DEFINE FIELD root_user     ON org_instance TYPE string;
-- AES-GCM sealed root password. Never stored in plaintext when INSTANCE_SECRET_KEY
-- is configured; the API opens it in memory only to sign in.
DEFINE FIELD root_pass_ref ON org_instance TYPE string;
DEFINE FIELD host          ON org_instance TYPE option<string>;
DEFINE FIELD created_at    ON org_instance TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD updated_at    ON org_instance TYPE datetime VALUE time::now();

-- One instance per organization. The UNIQUE index is also the cross-process guard
-- against two concurrent first-database requests both provisioning: the loser's
-- CREATE fails and it re-reads the winner's row.
DEFINE INDEX idx_org_instance_org ON org_instance FIELDS organization UNIQUE;
