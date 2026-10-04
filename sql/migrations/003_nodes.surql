-- ── feed_state: the global change counter ─────────────────────────────────────
-- Every accepted node write and every grant change takes the next value inside
-- its transaction. Incrementing this one row makes concurrent writers conflict at
-- commit, so commit order equals seq order and a pull cursor never skips a
-- change that commits late.
DEFINE TABLE feed_state SCHEMAFULL;
DEFINE FIELD seq ON feed_state TYPE int DEFAULT 0;
CREATE feed_state:main SET seq = 0;

DEFINE FUNCTION fn::next_seq() {
    RETURN (UPDATE ONLY feed_state:main SET seq += 1).seq;
};

-- ── node: one encrypted tree entry ────────────────────────────────────────────
-- The record id is the client-chosen UUID, so signatures and AAD bind it before
-- upload. The server stores ciphertext, wrapped keys and signatures verbatim and
-- never decrypts. `ancestors` is the precomputed path of ancestor ids, root
-- first, maintained by the server on write and on re-parenting.
DEFINE TABLE node SCHEMAFULL;
DEFINE FIELD owner          ON node TYPE record<user> READONLY;
DEFINE FIELD parent         ON node TYPE option<record<node>>;
DEFINE FIELD ancestors      ON node TYPE array<record<node>> DEFAULT [];
DEFINE FIELD collection     ON node TYPE string READONLY
    ASSERT $value IN ["calendar", "contacts", "photos", "files", "google"];
DEFINE FIELD kind           ON node TYPE string READONLY
    ASSERT $value IN ["root", "container", "item"];
DEFINE FIELD epoch          ON node TYPE int;
-- NONE only for roots
DEFINE FIELD wrapped_key    ON node TYPE option<string>;
DEFINE FIELD content        ON node TYPE array<object> DEFAULT [];
DEFINE FIELD content[*].facet      ON node TYPE int;
DEFINE FIELD content[*].ciphertext ON node TYPE string;
-- Blob reference as the compact JSON the author signed; served back verbatim.
DEFINE FIELD blob           ON node TYPE option<string>;
-- Total stored bytes (original plus variants) and every object id, for quota and presign checks.
DEFINE FIELD blob_size      ON node TYPE int DEFAULT 0;
DEFINE FIELD blob_objects   ON node TYPE array<string> DEFAULT [];
DEFINE FIELD deleted        ON node TYPE bool DEFAULT false;
DEFINE FIELD deleted_at     ON node TYPE option<datetime>;
DEFINE FIELD base_seq       ON node TYPE int;
DEFINE FIELD seq            ON node TYPE int;
DEFINE FIELD author_type    ON node TYPE string ASSERT $value IN ["user", "install"];
DEFINE FIELD author_id      ON node TYPE string;
DEFINE FIELD cert_id        ON node TYPE option<string>;
DEFINE FIELD signature      ON node TYPE string;
-- Set when a principal that held the node key lost access; the owner's next
-- vault session rotates the key and clears it.
DEFINE FIELD needs_rotation ON node TYPE bool DEFAULT false;
DEFINE FIELD created_at     ON node TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD updated_at     ON node TYPE datetime VALUE time::now();

DEFINE INDEX idx_node_seq        ON node FIELDS seq UNIQUE;
DEFINE INDEX idx_node_owner      ON node FIELDS owner;
DEFINE INDEX idx_node_parent     ON node FIELDS parent;
DEFINE INDEX idx_node_ancestors  ON node FIELDS ancestors;
DEFINE INDEX idx_node_deleted_at ON node FIELDS deleted_at;
DEFINE INDEX idx_node_cert       ON node FIELDS cert_id;

-- ── node_version: append-only history ─────────────────────────────────────────
-- A full snapshot of every accepted write, including everything its signature
-- covers, so any past version can be verified on its own.
DEFINE TABLE node_version SCHEMAFULL;
DEFINE FIELD node         ON node_version TYPE record<node> READONLY;
DEFINE FIELD parent       ON node_version TYPE option<record<node>> READONLY;
DEFINE FIELD collection   ON node_version TYPE string READONLY;
DEFINE FIELD kind         ON node_version TYPE string READONLY;
DEFINE FIELD epoch        ON node_version TYPE int READONLY;
DEFINE FIELD wrapped_key  ON node_version TYPE option<string> READONLY;
DEFINE FIELD content      ON node_version TYPE array<object> READONLY;
DEFINE FIELD content[*].facet      ON node_version TYPE int;
DEFINE FIELD content[*].ciphertext ON node_version TYPE string;
DEFINE FIELD blob         ON node_version TYPE option<string> READONLY;
DEFINE FIELD blob_objects ON node_version TYPE array<string> READONLY;
DEFINE FIELD deleted      ON node_version TYPE bool READONLY;
DEFINE FIELD base_seq     ON node_version TYPE int READONLY;
DEFINE FIELD seq          ON node_version TYPE int READONLY;
DEFINE FIELD author_type  ON node_version TYPE string READONLY;
DEFINE FIELD author_id    ON node_version TYPE string READONLY;
DEFINE FIELD cert_id      ON node_version TYPE option<string> READONLY;
DEFINE FIELD signature    ON node_version TYPE string READONLY;
DEFINE FIELD created_at   ON node_version TYPE datetime VALUE time::now() READONLY;

DEFINE INDEX idx_node_version_node ON node_version FIELDS node, seq;

-- ── access_grant: who may use a node, and the key material to do so ──────────
-- One row per (node, principal); a re-grant or a revoke updates it in place and
-- takes a new seq so the principal's next pull sees the change. The history of
-- every change lives in access_log. `facets` NONE grants the whole node and its
-- subtree; a facet list grants those facets of that node only.
DEFINE TABLE access_grant SCHEMAFULL;
DEFINE FIELD node            ON access_grant TYPE record<node> READONLY;
DEFINE FIELD principal_type  ON access_grant TYPE string READONLY
    ASSERT $value IN ["user", "install"];
DEFINE FIELD principal_id    ON access_grant TYPE string READONLY;
DEFINE FIELD role            ON access_grant TYPE string
    ASSERT $value IN ["read", "write", "admin"];
DEFINE FIELD facets          ON access_grant TYPE option<array<int>>;
DEFINE FIELD epoch           ON access_grant TYPE int;
DEFINE FIELD wrapped_keys    ON access_grant TYPE string;
DEFINE FIELD granted_by_type ON access_grant TYPE string ASSERT $value IN ["user", "install"];
DEFINE FIELD granted_by_id   ON access_grant TYPE string;
DEFINE FIELD cert_id         ON access_grant TYPE option<string>;
DEFINE FIELD signature       ON access_grant TYPE string;
DEFINE FIELD seq             ON access_grant TYPE int;
DEFINE FIELD created_at      ON access_grant TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD revoked_at      ON access_grant TYPE option<datetime>;

DEFINE INDEX idx_access_grant_unique    ON access_grant FIELDS node, principal_type, principal_id UNIQUE;
DEFINE INDEX idx_access_grant_principal ON access_grant FIELDS principal_type, principal_id;
DEFINE INDEX idx_access_grant_seq       ON access_grant FIELDS seq;

-- ── access_log: append-only audit trail of grants and revocations ────────────
-- Grant entries carry the granter's signature over the grant, so clients can
-- verify that the server did not add a member on its own.
DEFINE TABLE access_log SCHEMAFULL;
DEFINE FIELD node            ON access_log TYPE record<node> READONLY;
DEFINE FIELD action          ON access_log TYPE string READONLY ASSERT $value IN ["grant", "revoke"];
DEFINE FIELD principal_type  ON access_log TYPE string READONLY;
DEFINE FIELD principal_id    ON access_log TYPE string READONLY;
DEFINE FIELD role            ON access_log TYPE option<string> READONLY;
DEFINE FIELD facets          ON access_log TYPE option<array<int>> READONLY;
DEFINE FIELD epoch           ON access_log TYPE option<int> READONLY;
DEFINE FIELD wrapped_keys    ON access_log TYPE option<string> READONLY;
DEFINE FIELD actor_type      ON access_log TYPE string READONLY;
DEFINE FIELD actor_id        ON access_log TYPE string READONLY;
DEFINE FIELD cert_id         ON access_log TYPE option<string> READONLY;
DEFINE FIELD signature       ON access_log TYPE option<string> READONLY;
DEFINE FIELD created_at      ON access_log TYPE datetime VALUE time::now() READONLY;

DEFINE INDEX idx_access_log_node ON access_log FIELDS node;

-- ── link: an unauthenticated share of a node's subtree ───────────────────────
-- The node key travels in the URL fragment and never reaches the server.
DEFINE TABLE link SCHEMAFULL;
DEFINE FIELD node       ON link TYPE record<node> READONLY;
DEFINE FIELD created_by ON link TYPE record<user> READONLY;
DEFINE FIELD created_at ON link TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD revoked_at ON link TYPE option<datetime>;

DEFINE INDEX idx_link_node ON link FIELDS node;

-- ── purge_horizon: per owner, the newest tombstone seq that has been purged ──
-- A cursor older than this may have missed a deletion; pull answers 410 and the
-- client resyncs from scratch.
DEFINE TABLE purge_horizon SCHEMAFULL;
DEFINE FIELD user       ON purge_horizon TYPE record<user> READONLY;
DEFINE FIELD seq        ON purge_horizon TYPE int DEFAULT 0;
DEFINE FIELD updated_at ON purge_horizon TYPE datetime VALUE time::now();

DEFINE INDEX idx_purge_horizon_user ON purge_horizon FIELDS user UNIQUE;

-- ── Shared transaction fragments ─────────────────────────────────────────────
-- Flags a node (and its subtree for a whole-node grant) so the owner's next vault
-- session rotates its key. Each touched node takes a new seq so the owner's pull
-- sees the flag.
DEFINE FUNCTION fn::flag_for_rotation($node: record<node>, $whole_node: bool) {
    LET $targets = IF $whole_node {
        (SELECT VALUE id FROM node WHERE id = $node OR $node IN ancestors)
    } ELSE {
        [$node]
    };
    FOR $target IN $targets {
        UPDATE $target SET needs_rotation = true, seq = fn::next_seq();
    };
};

-- Revokes one grant, appends the revocation to access_log and flags the keys the
-- principal held for rotation. Revoking an already revoked grant does nothing.
DEFINE FUNCTION fn::revoke_grant($grant: record<access_grant>, $actor_type: string, $actor_id: string) {
    LET $row = (SELECT * FROM ONLY $grant);
    IF $row != NONE AND $row.revoked_at = NONE {
        UPDATE $grant SET revoked_at = time::now(), seq = fn::next_seq();
        CREATE access_log SET
            node = $row.node, action = 'revoke',
            principal_type = $row.principal_type, principal_id = $row.principal_id,
            actor_type = $actor_type, actor_id = $actor_id;
        fn::flag_for_rotation($row.node, $row.facets = NONE);
    };
};
