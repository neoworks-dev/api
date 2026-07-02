-- ════════════════════════════════════════════════════════════════════════
--  VERSIONED DATA LAYER — Complete Schema
-- ════════════════════════════════════════════════════════════════════════
--  Conventions:
--   - One shared `ref` table for all versioned entities.
--   - Each versioned entity has its own table; rows are immutable versions.
--   - Plain tables are normal CRUD, no versioning.
--   - Blobs are chunked and content-addressed.
--   - Holds are application-acquired refcount contributions.
-- ════════════════════════════════════════════════════════════════════════


-- ──────────────────────────────────────────────────────────────────────
--  1. SHARED REF TABLE
-- ──────────────────────────────────────────────────────────────────────
DEFINE TABLE ref SCHEMAFULL;
DEFINE FIELD entity_type ON ref TYPE string                        READONLY;
DEFINE FIELD head        ON ref TYPE option<record>;
DEFINE FIELD created_at  ON ref TYPE datetime VALUE time::now()    READONLY;
DEFINE FIELD created_by  ON ref TYPE option<record<ref>>           READONLY;
DEFINE FIELD deleted_at  ON ref TYPE option<datetime>;
DEFINE FIELD merged_into ON ref TYPE option<record<ref>>;

DEFINE INDEX idx_ref_type         ON TABLE ref COLUMNS entity_type;
DEFINE INDEX idx_ref_type_deleted ON TABLE ref COLUMNS entity_type, deleted_at;
DEFINE INDEX idx_ref_created_by   ON TABLE ref COLUMNS created_by;
DEFINE INDEX idx_ref_merged_into  ON TABLE ref COLUMNS merged_into;


-- ──────────────────────────────────────────────────────────────────────
--  2. SCHEMA REGISTRY (lets the SDK ask "is this table versioned?")
-- ──────────────────────────────────────────────────────────────────────
DEFINE TABLE schema_table SCHEMAFULL;
DEFINE FIELD name        ON schema_table TYPE string;
DEFINE FIELD versioned   ON schema_table TYPE bool;
DEFINE FIELD blob_fields ON schema_table TYPE array<string> DEFAULT [];
DEFINE FIELD audit       ON schema_table TYPE bool          DEFAULT true;
DEFINE INDEX idx_schema_name ON TABLE schema_table COLUMNS name UNIQUE;


-- ──────────────────────────────────────────────────────────────────────
--  3. BLOB STORAGE (content-addressed, chunked)
-- ──────────────────────────────────────────────────────────────────────
DEFINE TABLE chunk SCHEMAFULL;
DEFINE FIELD hash       ON chunk TYPE string                     READONLY;
DEFINE FIELD size       ON chunk TYPE int                        READONLY;
DEFINE FIELD storage    ON chunk TYPE string                     READONLY;
DEFINE FIELD data       ON chunk TYPE option<bytes>              READONLY;
DEFINE FIELD refs       ON chunk TYPE int  DEFAULT 0;
DEFINE FIELD created_at ON chunk TYPE datetime VALUE time::now() READONLY;

DEFINE INDEX idx_chunk_hash ON TABLE chunk COLUMNS hash UNIQUE;
DEFINE INDEX idx_chunk_refs ON TABLE chunk COLUMNS refs;

DEFINE TABLE blob SCHEMAFULL;
DEFINE FIELD hash       ON blob TYPE string                       READONLY;
DEFINE FIELD size       ON blob TYPE int                          READONLY;
DEFINE FIELD mime       ON blob TYPE string                       READONLY;
DEFINE FIELD chunks     ON blob TYPE array<record<chunk>>         READONLY;
DEFINE FIELD refs       ON blob TYPE int  DEFAULT 0;
DEFINE FIELD created_at ON blob TYPE datetime VALUE time::now()   READONLY;
DEFINE FIELD created_by ON blob TYPE option<record<ref>>          READONLY;

DEFINE INDEX idx_blob_hash ON TABLE blob COLUMNS hash UNIQUE;
DEFINE INDEX idx_blob_refs ON TABLE blob COLUMNS refs;


-- ──────────────────────────────────────────────────────────────────────
--  4. HOLDS (refcount contributions from application subsystems)
-- ──────────────────────────────────────────────────────────────────────
DEFINE TABLE hold SCHEMAFULL;
DEFINE FIELD target     ON hold TYPE record                       READONLY;
DEFINE FIELD holder     ON hold TYPE string                       READONLY;
DEFINE FIELD holder_id  ON hold TYPE option<string>               READONLY;
DEFINE FIELD reason     ON hold TYPE option<string>               READONLY;
DEFINE FIELD created_at ON hold TYPE datetime VALUE time::now()   READONLY;
DEFINE FIELD expires_at ON hold TYPE option<datetime>;

DEFINE INDEX idx_hold_target ON TABLE hold COLUMNS target;
DEFINE INDEX idx_hold_holder ON TABLE hold COLUMNS holder, holder_id UNIQUE;
DEFINE INDEX idx_hold_expiry ON TABLE hold COLUMNS expires_at;


-- ──────────────────────────────────────────────────────────────────────
--  5. AUDIT LOG (append-only, no versioning needed)
-- ──────────────────────────────────────────────────────────────────────
DEFINE TABLE audit_event SCHEMAFULL;
DEFINE FIELD actor      ON audit_event TYPE option<record<ref>>   READONLY;
DEFINE FIELD action     ON audit_event TYPE string                READONLY;
DEFINE FIELD target     ON audit_event TYPE option<record>        READONLY;
DEFINE FIELD payload    ON audit_event TYPE option<object>        READONLY;
DEFINE FIELD ip         ON audit_event TYPE option<string>        READONLY;
DEFINE FIELD created_at ON audit_event TYPE datetime VALUE time::now() READONLY;

DEFINE INDEX idx_audit_target ON TABLE audit_event COLUMNS target;
DEFINE INDEX idx_audit_actor  ON TABLE audit_event COLUMNS actor;
DEFINE INDEX idx_audit_action ON TABLE audit_event COLUMNS action;
DEFINE INDEX idx_audit_time   ON TABLE audit_event COLUMNS created_at;


-- ══════════════════════════════════════════════════════════════════════
--  6. HELPER FUNCTIONS
-- ══════════════════════════════════════════════════════════════════════

-- ─── Structural refcount: head + parent references ────────────────────
DEFINE FUNCTION fn::structural_refs($v: record) {
    LET $tbl       = type::table($v);
    LET $as_head   = (SELECT VALUE id FROM ref WHERE head = $v LIMIT 1);
    LET $as_parent = (SELECT VALUE id FROM type::table($tbl) WHERE parent = $v LIMIT 1);
    RETURN (IF $as_head  THEN 1 ELSE 0 END)
         + (IF $as_parent THEN 1 ELSE 0 END);
};

-- ─── Full recount = structural + application holds ────────────────────
DEFINE FUNCTION fn::recount_version($v: option<record>) {
    IF $v = NONE { RETURN NONE };
    LET $app    = (SELECT count() FROM hold WHERE target = $v GROUP ALL)[0].count ?? 0;
    LET $struct = fn::structural_refs($v);
    UPDATE $v SET refcount = $struct + $app;
};

-- ─── Soft-delete a ref ────────────────────────────────────────────────
DEFINE FUNCTION fn::soft_delete_ref($ref: record<ref>) {
    UPDATE $ref SET deleted_at = time::now();
};

-- ─── Restore a soft-deleted ref ───────────────────────────────────────
DEFINE FUNCTION fn::restore_ref($ref: record<ref>) {
    UPDATE $ref SET deleted_at = NONE;
};

-- ─── Sweep expired holds (run periodically) ───────────────────────────
DEFINE FUNCTION fn::sweep_expired_holds() {
    DELETE hold WHERE expires_at != NONE AND expires_at < time::now();
};


-- ══════════════════════════════════════════════════════════════════════
--  7. EVENTS — keep refcounts current automatically
-- ══════════════════════════════════════════════════════════════════════

-- ─── Hold lifecycle → recount target ──────────────────────────────────
DEFINE EVENT hold_changed ON TABLE hold WHEN $event IN ['CREATE','DELETE'] THEN {
    LET $target = $after.target ?? $before.target;
    fn::recount_version($target);
};

-- ─── Ref head moves → recount old and new heads ───────────────────────
DEFINE EVENT ref_head_changed ON TABLE ref
    WHEN $event = 'UPDATE' AND $before.head != $after.head
    THEN {
        fn::recount_version($before.head);
        fn::recount_version($after.head);
    };


-- ══════════════════════════════════════════════════════════════════════
--  8. VERSIONED ENTITY TABLES
-- ══════════════════════════════════════════════════════════════════════
--  Template repeated per entity. The block of versioning fields and
--  indexes is identical for every versioned table.
-- ══════════════════════════════════════════════════════════════════════




-- ─── 8d. scope_definition ─────────────────────────────────────────────
DEFINE TABLE scope_definition SCHEMAFULL;
DEFINE FIELD ref          ON scope_definition TYPE record<ref>                    READONLY;
DEFINE FIELD seq          ON scope_definition TYPE int                            READONLY;
DEFINE FIELD parent       ON scope_definition TYPE option<record<scope_definition>> READONLY;
DEFINE FIELD created_at   ON scope_definition TYPE datetime VALUE time::now()     READONLY;
DEFINE FIELD created_by   ON scope_definition TYPE option<record<ref>>            READONLY;
DEFINE FIELD is_head      ON scope_definition TYPE bool DEFAULT false;
DEFINE FIELD pinned       ON scope_definition TYPE bool DEFAULT false;
DEFINE FIELD refcount     ON scope_definition TYPE int  DEFAULT 0;
DEFINE FIELD message      ON scope_definition TYPE option<string>                 READONLY;
DEFINE FIELD name         ON scope_definition TYPE string;
DEFINE FIELD description  ON scope_definition TYPE option<string>;
DEFINE INDEX idx_scope_ref_seq   ON TABLE scope_definition COLUMNS ref, seq UNIQUE;
DEFINE INDEX idx_scope_head      ON TABLE scope_definition COLUMNS is_head, ref;
DEFINE INDEX idx_scope_parent    ON TABLE scope_definition COLUMNS parent;
DEFINE INDEX idx_scope_refcount  ON TABLE scope_definition COLUMNS refcount;
DEFINE INDEX idx_scope_name      ON TABLE scope_definition COLUMNS name;
DEFINE EVENT scope_created ON TABLE scope_definition
    WHEN $event = 'CREATE' AND $after.parent != NONE
    THEN { fn::recount_version($after.parent); };


-- ─── 8e. permission_policy ────────────────────────────────────────────
DEFINE TABLE permission_policy SCHEMAFULL;
DEFINE FIELD ref          ON permission_policy TYPE record<ref>                     READONLY;
DEFINE FIELD seq          ON permission_policy TYPE int                             READONLY;
DEFINE FIELD parent       ON permission_policy TYPE option<record<permission_policy>> READONLY;
DEFINE FIELD created_at   ON permission_policy TYPE datetime VALUE time::now()      READONLY;
DEFINE FIELD created_by   ON permission_policy TYPE option<record<ref>>             READONLY;
DEFINE FIELD is_head      ON permission_policy TYPE bool DEFAULT false;
DEFINE FIELD pinned       ON permission_policy TYPE bool DEFAULT false;
DEFINE FIELD refcount     ON permission_policy TYPE int  DEFAULT 0;
DEFINE FIELD message      ON permission_policy TYPE option<string>                  READONLY;
DEFINE FIELD name         ON permission_policy TYPE string;
DEFINE FIELD rules        ON permission_policy TYPE array<object>;
DEFINE FIELD applies_to   ON permission_policy TYPE array<record<ref>>;
DEFINE INDEX idx_policy_ref_seq   ON TABLE permission_policy COLUMNS ref, seq UNIQUE;
DEFINE INDEX idx_policy_head      ON TABLE permission_policy COLUMNS is_head, ref;
DEFINE INDEX idx_policy_parent    ON TABLE permission_policy COLUMNS parent;
DEFINE INDEX idx_policy_refcount  ON TABLE permission_policy COLUMNS refcount;
DEFINE INDEX idx_policy_name      ON TABLE permission_policy COLUMNS name;
DEFINE INDEX idx_policy_applies   ON TABLE permission_policy COLUMNS applies_to;
DEFINE EVENT policy_created ON TABLE permission_policy
    WHEN $event = 'CREATE' AND $after.parent != NONE
    THEN { fn::recount_version($after.parent); };


-- ─── 8f. contact ──────────────────────────────────────────────────────
DEFINE TABLE contact SCHEMAFULL;
DEFINE FIELD ref          ON contact TYPE record<ref>                READONLY;
DEFINE FIELD seq          ON contact TYPE int                        READONLY;
DEFINE FIELD parent       ON contact TYPE option<record<contact>>    READONLY;
DEFINE FIELD created_at   ON contact TYPE datetime VALUE time::now() READONLY;
DEFINE FIELD created_by   ON contact TYPE option<record<ref>>        READONLY;
DEFINE FIELD is_head      ON contact TYPE bool DEFAULT false;
DEFINE FIELD pinned       ON contact TYPE bool DEFAULT false;
DEFINE FIELD refcount     ON contact TYPE int  DEFAULT 0;
DEFINE FIELD message      ON contact TYPE option<string>             READONLY;
DEFINE FIELD given_name   ON contact TYPE option<string>;
DEFINE FIELD family_name  ON contact TYPE option<string>;
DEFINE FIELD phones       ON contact TYPE array<object> DEFAULT [];
DEFINE FIELD emails       ON contact TYPE array<object> DEFAULT [];
DEFINE FIELD addresses    ON contact TYPE array<object> DEFAULT [];
DEFINE FIELD birthday     ON contact TYPE option<datetime>;
DEFINE FIELD note         ON contact TYPE option<string>;
DEFINE INDEX idx_contact_ref_seq   ON TABLE contact COLUMNS ref, seq UNIQUE;
DEFINE INDEX idx_contact_head      ON TABLE contact COLUMNS is_head, ref;
DEFINE INDEX idx_contact_parent    ON TABLE contact COLUMNS parent;
DEFINE INDEX idx_contact_refcount  ON TABLE contact COLUMNS refcount;
DEFINE INDEX idx_contact_phone     ON TABLE contact COLUMNS phones.*.value;
DEFINE INDEX idx_contact_email     ON TABLE contact COLUMNS emails.*.value;
DEFINE INDEX idx_contact_name      ON TABLE contact COLUMNS family_name, given_name;
DEFINE EVENT contact_created ON TABLE contact
    WHEN $event = 'CREATE' AND $after.parent != NONE
    THEN { fn::recount_version($after.parent); };


-- ══════════════════════════════════════════════════════════════════════
--  9. PLAIN (UNVERSIONED) TABLES
-- ══════════════════════════════════════════════════════════════════════

-- USER (plain)
DEFINE TABLE user SCHEMAFULL;
DEFINE FIELD email        ON user TYPE string;
DEFINE FIELD display_name ON user TYPE option<string>;
DEFINE FIELD avatar       ON user TYPE option<record<blob>>;
DEFINE FIELD created_at   ON user TYPE datetime VALUE time::now() READONLY;
DEFINE FIELD updated_at   ON user TYPE datetime VALUE time::now();
DEFINE FIELD deleted_at   ON user TYPE option<datetime>;
DEFINE INDEX idx_user_email   ON TABLE user COLUMNS email UNIQUE;
DEFINE INDEX idx_user_deleted ON TABLE user COLUMNS deleted_at;

-- ORGANIZATION (plain) — owns clients; a separate billing identity from any user
DEFINE TABLE organization SCHEMAFULL;
DEFINE FIELD name          ON organization TYPE string;
DEFINE FIELD slug          ON organization TYPE string;
DEFINE FIELD logo          ON organization TYPE option<record<blob>>;
DEFINE FIELD billing_email ON organization TYPE option<string>;
DEFINE FIELD created_at    ON organization TYPE datetime VALUE time::now() READONLY;
DEFINE FIELD updated_at    ON organization TYPE datetime VALUE time::now();
DEFINE FIELD deleted_at    ON organization TYPE option<datetime>;
DEFINE INDEX idx_org_slug    ON TABLE organization COLUMNS slug UNIQUE;
DEFINE INDEX idx_org_deleted ON TABLE organization COLUMNS deleted_at;

-- MEMBERSHIP (relation) — user ↔ organization, many-to-many, carries a role
DEFINE TABLE membership SCHEMAFULL TYPE RELATION IN user OUT organization;
DEFINE FIELD role       ON membership TYPE string DEFAULT "member"
    ASSERT $value IN ["owner", "admin", "member", "billing"];
DEFINE FIELD created_at ON membership TYPE datetime VALUE time::now() READONLY;
DEFINE INDEX idx_membership_unique ON TABLE membership COLUMNS in, out UNIQUE;

-- CLIENT (plain) — owned by an organization, never by a user directly
DEFINE TABLE client SCHEMAFULL;
DEFINE FIELD name           ON client TYPE string;
DEFINE FIELD client_id      ON client TYPE string;
DEFINE FIELD redirect_uris  ON client TYPE array<string>;
DEFINE FIELD allowed_scopes ON client TYPE array<string>;
DEFINE FIELD description    ON client TYPE option<string>;
DEFINE FIELD logo           ON client TYPE option<record<blob>>;
DEFINE FIELD organization   ON client TYPE record<organization>;
DEFINE FIELD created_by     ON client TYPE option<record<user>>;  -- audit only, not ownership
DEFINE FIELD created_at     ON client TYPE datetime VALUE time::now() READONLY;
DEFINE FIELD updated_at     ON client TYPE datetime VALUE time::now();
DEFINE FIELD deleted_at     ON client TYPE option<datetime>;
DEFINE INDEX idx_client_id      ON TABLE client COLUMNS client_id UNIQUE;
DEFINE INDEX idx_client_org     ON TABLE client COLUMNS organization;
DEFINE INDEX idx_client_deleted ON TABLE client COLUMNS deleted_at;


-- ─── 9a. oauth_access_token ───────────────────────────────────────────
DEFINE TABLE oauth_access_token SCHEMAFULL;
DEFINE FIELD token_hash     ON oauth_access_token TYPE string;
DEFINE FIELD client         ON oauth_access_token TYPE record<ref>;
DEFINE FIELD client_version ON oauth_access_token TYPE record<client>;
DEFINE FIELD subject        ON oauth_access_token TYPE record<ref>;
DEFINE FIELD scopes         ON oauth_access_token TYPE array<string>;
DEFINE FIELD issued_at      ON oauth_access_token TYPE datetime VALUE time::now() READONLY;
DEFINE FIELD expires_at     ON oauth_access_token TYPE datetime;
DEFINE FIELD revoked_at     ON oauth_access_token TYPE option<datetime>;
DEFINE INDEX idx_token_hash    ON TABLE oauth_access_token COLUMNS token_hash UNIQUE;
DEFINE INDEX idx_token_subject ON TABLE oauth_access_token COLUMNS subject;
DEFINE INDEX idx_token_client  ON TABLE oauth_access_token COLUMNS client;
DEFINE INDEX idx_token_expires ON TABLE oauth_access_token COLUMNS expires_at;

-- ─── 9b. oauth_refresh_token ──────────────────────────────────────────
DEFINE TABLE oauth_refresh_token SCHEMAFULL;
DEFINE FIELD token_hash     ON oauth_refresh_token TYPE string;
DEFINE FIELD client         ON oauth_refresh_token TYPE record<ref>;
DEFINE FIELD client_version ON oauth_refresh_token TYPE record<client>;
DEFINE FIELD subject        ON oauth_refresh_token TYPE record<ref>;
DEFINE FIELD scopes         ON oauth_refresh_token TYPE array<string>;
DEFINE FIELD issued_at      ON oauth_refresh_token TYPE datetime VALUE time::now() READONLY;
DEFINE FIELD expires_at     ON oauth_refresh_token TYPE datetime;
DEFINE FIELD revoked_at     ON oauth_refresh_token TYPE option<datetime>;
DEFINE INDEX idx_refresh_hash    ON TABLE oauth_refresh_token COLUMNS token_hash UNIQUE;
DEFINE INDEX idx_refresh_subject ON TABLE oauth_refresh_token COLUMNS subject;
DEFINE INDEX idx_refresh_expires ON TABLE oauth_refresh_token COLUMNS expires_at;

-- ─── 9c. oauth_authorization_code ─────────────────────────────────────
DEFINE TABLE oauth_authorization_code SCHEMAFULL;
DEFINE FIELD code                  ON oauth_authorization_code TYPE string;
DEFINE FIELD client                ON oauth_authorization_code TYPE record<ref>;
DEFINE FIELD client_version        ON oauth_authorization_code TYPE record<client>;
DEFINE FIELD subject               ON oauth_authorization_code TYPE record<ref>;
DEFINE FIELD redirect_uri          ON oauth_authorization_code TYPE string;
DEFINE FIELD scopes                ON oauth_authorization_code TYPE array<string>;
DEFINE FIELD code_challenge        ON oauth_authorization_code TYPE option<string>;
DEFINE FIELD code_challenge_method ON oauth_authorization_code TYPE option<string>;
DEFINE FIELD issued_at             ON oauth_authorization_code TYPE datetime VALUE time::now() READONLY;
DEFINE FIELD expires_at            ON oauth_authorization_code TYPE datetime;
DEFINE FIELD used_at               ON oauth_authorization_code TYPE option<datetime>;
DEFINE INDEX idx_authcode_code    ON TABLE oauth_authorization_code COLUMNS code UNIQUE;
DEFINE INDEX idx_authcode_client  ON TABLE oauth_authorization_code COLUMNS client;
DEFINE INDEX idx_authcode_expires ON TABLE oauth_authorization_code COLUMNS expires_at;

-- ─── 9d. session ──────────────────────────────────────────────────────
DEFINE TABLE session SCHEMAFULL;
DEFINE FIELD subject    ON session TYPE record<ref>;
DEFINE FIELD started_at ON session TYPE datetime VALUE time::now() READONLY;
DEFINE FIELD expires_at ON session TYPE datetime;
DEFINE FIELD last_seen  ON session TYPE datetime VALUE time::now();
DEFINE FIELD user_agent ON session TYPE option<string>;
DEFINE FIELD ip         ON session TYPE option<string>;
DEFINE INDEX idx_session_subject ON TABLE session COLUMNS subject;
DEFINE INDEX idx_session_expires ON TABLE session COLUMNS expires_at;

-- ─── 9e. rate_limit_counter ───────────────────────────────────────────
DEFINE TABLE rate_limit_counter SCHEMAFULL;
DEFINE FIELD bucket ON rate_limit_counter TYPE string;
DEFINE FIELD window ON rate_limit_counter TYPE datetime;
DEFINE FIELD count  ON rate_limit_counter TYPE int DEFAULT 0;
DEFINE INDEX idx_rl_bucket_window ON TABLE rate_limit_counter COLUMNS bucket, window UNIQUE;


-- ══════════════════════════════════════════════════════════════════════
--  10. SEED SCHEMA REGISTRY
-- ══════════════════════════════════════════════════════════════════════
CREATE schema_table SET name = 'user',              versioned = true,  blob_fields = ['avatar'];
CREATE schema_table SET name = 'organization',      versioned = false, blob_fields = ['logo'];
CREATE schema_table SET name = 'membership',        versioned = false;
CREATE schema_table SET name = 'client',            versioned = true,  blob_fields = ['logo'];
CREATE schema_table SET name = 'resource_server',   versioned = true,  blob_fields = [];
CREATE schema_table SET name = 'scope_definition',  versioned = true,  blob_fields = [];
CREATE schema_table SET name = 'permission_policy', versioned = true,  blob_fields = [];
CREATE schema_table SET name = 'contact',           versioned = true,  blob_fields = [];
CREATE schema_table SET name = 'oauth_access_token',       versioned = false;
CREATE schema_table SET name = 'oauth_refresh_token',      versioned = false;
CREATE schema_table SET name = 'oauth_authorization_code', versioned = false;
CREATE schema_table SET name = 'session',                  versioned = false;
CREATE schema_table SET name = 'rate_limit_counter',       versioned = false;
