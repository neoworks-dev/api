-- ── OpenSchema registry: public schemas, publishable by any signed-in user ───
-- Schemas are plain (not end-to-end encrypted) rows. Scope and name form the
-- public path `@scope/name`. The first publisher owns the schema; only the owner
-- publishes further versions. Versions and their files are immutable.

DEFINE ANALYZER registry_text TOKENIZERS class FILTERS lowercase, ascii;

DEFINE TABLE registry_schema SCHEMAFULL;
DEFINE FIELD scope           ON registry_schema TYPE string;
DEFINE FIELD name            ON registry_schema TYPE string;
DEFINE FIELD owner           ON registry_schema TYPE record<user> READONLY;
-- title, description, license and repository follow the latest published manifest.
DEFINE FIELD title           ON registry_schema TYPE string;
DEFINE FIELD description     ON registry_schema TYPE string;
DEFINE FIELD tags            ON registry_schema TYPE array<string> DEFAULT [];
DEFINE FIELD license         ON registry_schema TYPE string DEFAULT '';
DEFINE FIELD repository      ON registry_schema TYPE string DEFAULT '';
DEFINE FIELD latest_version  ON registry_schema TYPE string;
DEFINE FIELD official        ON registry_schema TYPE bool DEFAULT false;
DEFINE FIELD downloads_total ON registry_schema TYPE int DEFAULT 0;
DEFINE FIELD created_at      ON registry_schema TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD updated_at      ON registry_schema TYPE datetime VALUE time::now();

DEFINE INDEX idx_registry_schema_path        ON registry_schema FIELDS scope, name UNIQUE;
DEFINE INDEX idx_registry_schema_name_text   ON registry_schema FIELDS name FULLTEXT ANALYZER registry_text BM25;
DEFINE INDEX idx_registry_schema_title_text  ON registry_schema FIELDS title FULLTEXT ANALYZER registry_text BM25;
DEFINE INDEX idx_registry_schema_desc_text   ON registry_schema FIELDS description FULLTEXT ANALYZER registry_text BM25;

-- Append-only: a published version is never changed.
DEFINE TABLE registry_schema_version SCHEMAFULL;
DEFINE FIELD schema      ON registry_schema_version TYPE record<registry_schema> READONLY;
DEFINE FIELD version     ON registry_schema_version TYPE string READONLY;
DEFINE FIELD state       ON registry_schema_version TYPE string DEFAULT 'released' READONLY;
DEFINE FIELD readme      ON registry_schema_version TYPE string DEFAULT '' READONLY;
DEFINE FIELD targets     ON registry_schema_version TYPE array<string> DEFAULT [] READONLY;
DEFINE FIELD released_at ON registry_schema_version TYPE datetime VALUE time::now() READONLY;
DEFINE FIELD created_at  ON registry_schema_version TYPE datetime VALUE time::now() READONLY;
-- The descriptor target's output, present when the schema defines Neoworks nodes;
-- descriptor_hash is base64url(BLAKE2b-256(descriptor bytes)).
DEFINE FIELD descriptor      ON registry_schema_version TYPE option<string> READONLY;
DEFINE FIELD descriptor_hash ON registry_schema_version TYPE option<string> READONLY;

DEFINE INDEX idx_registry_version_unique     ON registry_schema_version FIELDS schema, version UNIQUE;
DEFINE INDEX idx_registry_version_descriptor ON registry_schema_version FIELDS schema, descriptor_hash;

DEFINE TABLE registry_schema_file SCHEMAFULL;
DEFINE FIELD version  ON registry_schema_file TYPE record<registry_schema_version> READONLY;
DEFINE FIELD path     ON registry_schema_file TYPE string READONLY;
DEFINE FIELD contents ON registry_schema_file TYPE string READONLY;
DEFINE FIELD size     ON registry_schema_file TYPE int READONLY;
DEFINE FIELD ordinal  ON registry_schema_file TYPE int READONLY;

DEFINE INDEX idx_registry_file_version ON registry_schema_file FIELDS version;
