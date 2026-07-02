-- A client may own up to 5 databases, provisioned on separate SurrealDB
-- infrastructure so client data is isolated from Neoworks' internal database.
DEFINE TABLE client_database SCHEMAFULL;
DEFINE FIELD client      ON client_database TYPE record<client> READONLY;
DEFINE FIELD name        ON client_database TYPE string         READONLY;
DEFINE FIELD db_name     ON client_database TYPE string         READONLY;
-- the client's submitted schema verbatim: { tables: [ { name, schemafull, fields, indexes }, ... ] }.
-- FLEXIBLE so the nested objects/arrays are stored without per-key type enforcement.
DEFINE FIELD schema_def  ON client_database TYPE option<object> FLEXIBLE;
DEFINE FIELD status      ON client_database TYPE string DEFAULT "active"
    ASSERT $value IN ["active", "suspended", "deleted"];
DEFINE FIELD created_at  ON client_database TYPE datetime VALUE time::now()  READONLY;
DEFINE FIELD updated_at  ON client_database TYPE datetime VALUE time::now();

DEFINE INDEX idx_client_db_client ON client_database FIELDS client;
DEFINE INDEX idx_client_db_name   ON client_database FIELDS client, name UNIQUE;

-- Backstop for the 5-databases-per-client limit; the resolver also enforces it.
DEFINE EVENT client_database_cap ON client_database WHEN $event = "CREATE" THEN {
    LET $count = (SELECT count() FROM client_database
                  WHERE client = $after.client AND status != "deleted" GROUP ALL)[0].count ?? 0;
    IF $count > 5 { THROW "client database limit (5) exceeded"; };
};

-- One row per table inside a client_database, recorded AFTER the server has
-- validated and rewritten the submitted JSON schema. Clients never submit raw
-- SurrealDB schema; the server owns the validated form stored here, and GraphQL
-- endpoints are generated from this registry — never from raw client input.
DEFINE TABLE client_table SCHEMAFULL;
DEFINE FIELD database          ON client_table TYPE record<client_database> READONLY;
DEFINE FIELD name              ON client_table TYPE string                  READONLY;
-- data:     user-facing table; must carry subject_user_id
-- relation: edge table; traced to a user indirectly via subject_path
-- helper:   internal/support table; traced to a user indirectly via subject_path
DEFINE FIELD kind              ON client_table TYPE string
    ASSERT $value IN ["data", "relation", "helper"]                         READONLY;
DEFINE FIELD versioned         ON client_table TYPE bool DEFAULT false;     -- history requested in the JSON schema
DEFINE FIELD has_subject_user  ON client_table TYPE bool DEFAULT true;
DEFINE FIELD subject_path      ON client_table TYPE option<string>;          -- relation/helper: how the row traces to a user
DEFINE FIELD validated_schema  ON client_table TYPE object FLEXIBLE;         -- the rewritten, server-owned schema
DEFINE FIELD created_at        ON client_table TYPE datetime VALUE time::now() READONLY;
DEFINE FIELD updated_at        ON client_table TYPE datetime VALUE time::now();

DEFINE INDEX idx_client_table_db     ON client_table FIELDS database;
DEFINE INDEX idx_client_table_unique ON client_table FIELDS database, name UNIQUE;
