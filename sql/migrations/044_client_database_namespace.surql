-- Client databases now live in a per-client SurrealDB namespace (client_{clientID})
-- rather than sharing the system namespace. The namespace is the top-level tenant
-- boundary and the unit future sharding routes. db_name now holds the logical name
-- within that namespace. Provisioning stamps namespace; client data is disposable
-- and re-provisioned, so no backfill is required.
DEFINE FIELD namespace ON client_database TYPE string READONLY;
