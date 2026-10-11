-- ── OpenSchema registry: public schemas, publishable by any signed-in user ───
-- Schemas are plain (not end-to-end encrypted) rows. Scope and name form the
-- public path `@scope/name`. The scope is a handle (see 009), so the schema is
-- owned by whoever holds that handle and is published by members holding
-- `schemas.publish`. Versions and their files are immutable.

DEFINE ANALYZER registry_text TOKENIZERS class FILTERS lowercase, ascii;

DEFINE TABLE registry_schema SCHEMAFULL;
DEFINE FIELD scope           ON registry_schema TYPE string;
DEFINE FIELD name            ON registry_schema TYPE string;
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

-- ── registry_publish: every publish attempt by a user acting for the scope ───
-- Accepted publishes and refused ones (an incompatible descriptor, an existing
-- version) with the violations that refused them. Append-only.
DEFINE TABLE registry_publish SCHEMAFULL;
DEFINE FIELD schema     ON registry_publish TYPE record<registry_schema> READONLY;
DEFINE FIELD version    ON registry_publish TYPE string READONLY;
DEFINE FIELD actor      ON registry_publish TYPE record<user> READONLY;
DEFINE FIELD accepted   ON registry_publish TYPE bool READONLY;
DEFINE FIELD violations ON registry_publish TYPE array<object> DEFAULT [] READONLY;
DEFINE FIELD violations.*.rule    ON registry_publish TYPE string;
DEFINE FIELD violations.*.path    ON registry_publish TYPE string;
DEFINE FIELD violations.*.message ON registry_publish TYPE string;
DEFINE FIELD created_at ON registry_publish TYPE datetime VALUE time::now() READONLY;

DEFINE INDEX idx_registry_publish_schema ON registry_publish FIELDS schema, created_at;
