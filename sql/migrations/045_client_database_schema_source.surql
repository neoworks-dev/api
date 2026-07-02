-- Clients now author database schemas in the OpenSchema DSL, compiled server-side
-- into the DatabaseSchemaInput shape. The DSL text is the canonical artifact;
-- schema_def keeps the derived compiled JSON for debugging.
DEFINE FIELD schema_source ON client_database TYPE option<string>;
