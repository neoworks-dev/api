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
-- never decrypts. Field names are the contract's, in snake_case; ids are plain
-- strings. `ancestors` is the precomputed path of ancestor ids, root first,
-- maintained by the server on write and on re-parenting.
--
-- `collection` is the registry path `@scope/name` of the schema the content
-- follows. `content` is base64url of one message with a LEN field per facet tag
-- holding that facet's ciphertext; roots and shortcuts have none. A shortcut is
-- an item standing for `target_id`, an item of the same collection: its wrapped
-- key is the target's key and whoever can open it holds at most `target_role`
-- on the target.
--
-- `seq` is always taken from the change counter when a node is created, whoever
-- creates it: a value supplied on create is ignored. Updates set it explicitly.
DEFINE TABLE node SCHEMAFULL;
DEFINE FIELD owner_id       ON node TYPE string READONLY;
DEFINE FIELD parent_id      ON node TYPE option<string>;
DEFINE FIELD ancestors      ON node TYPE array<string> DEFAULT [];
DEFINE FIELD collection     ON node TYPE string READONLY
    ASSERT string::matches($value, "^@[a-z0-9][a-z0-9._-]{0,63}/[a-z0-9][a-z0-9._-]{0,63}$");
DEFINE FIELD kind           ON node TYPE string READONLY
    ASSERT $value IN ["root", "container", "item"];
DEFINE FIELD epoch          ON node TYPE int;
-- NONE only for roots
DEFINE FIELD wrapped_key    ON node TYPE option<string>;
DEFINE FIELD content        ON node TYPE string DEFAULT "";
DEFINE FIELD target_id      ON node TYPE option<string> READONLY;
DEFINE FIELD target_role    ON node TYPE option<string> READONLY
    ASSERT $value = NONE OR $value IN ["read", "write"];
-- The blob reference as an object, and as the exact compact JSON the author
-- signed (an object loses key order, so the string is what is served).
DEFINE FIELD blob           ON node TYPE option<object> FLEXIBLE;
DEFINE FIELD blob_json      ON node TYPE option<string>;
-- Total stored bytes (original plus variants) and every object id, for quota and
-- presign checks. An object id belongs to one node: pushes that name another
-- node's object are refused, so presigned URLs can never reach a foreign object.
DEFINE FIELD blob_size      ON node TYPE int DEFAULT 0;
DEFINE FIELD blob_objects   ON node TYPE array<string> DEFAULT [];
DEFINE FIELD deleted        ON node TYPE bool DEFAULT false;
DEFINE FIELD deleted_at     ON node TYPE option<datetime>;
DEFINE FIELD base_seq       ON node TYPE int;
DEFINE FIELD seq            ON node TYPE int
    VALUE IF $before = NONE { fn::next_seq() } ELSE { $value };
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
DEFINE INDEX idx_node_owner      ON node FIELDS owner_id;
DEFINE INDEX idx_node_parent     ON node FIELDS parent_id;
DEFINE INDEX idx_node_ancestors  ON node FIELDS ancestors;
DEFINE INDEX idx_node_deleted_at ON node FIELDS deleted_at;
DEFINE INDEX idx_node_cert       ON node FIELDS cert_id;
DEFINE INDEX idx_node_objects    ON node FIELDS blob_objects;
DEFINE INDEX idx_node_target     ON node FIELDS target_id;

-- ── node_version: append-only history ─────────────────────────────────────────
-- A full snapshot of every accepted write, including everything its signature
-- covers, so any past version can be verified on its own.
DEFINE TABLE node_version SCHEMAFULL;
DEFINE FIELD node_id      ON node_version TYPE string READONLY;
DEFINE FIELD parent_id    ON node_version TYPE option<string> READONLY;
DEFINE FIELD collection   ON node_version TYPE string READONLY;
DEFINE FIELD kind         ON node_version TYPE string READONLY;
DEFINE FIELD epoch        ON node_version TYPE int READONLY;
DEFINE FIELD wrapped_key  ON node_version TYPE option<string> READONLY;
DEFINE FIELD content      ON node_version TYPE string READONLY;
DEFINE FIELD target_id    ON node_version TYPE option<string> READONLY;
DEFINE FIELD target_role  ON node_version TYPE option<string> READONLY;
DEFINE FIELD blob_json    ON node_version TYPE option<string> READONLY;
DEFINE FIELD blob_objects ON node_version TYPE array<string> READONLY;
DEFINE FIELD deleted      ON node_version TYPE bool READONLY;
DEFINE FIELD base_seq     ON node_version TYPE int READONLY;
DEFINE FIELD seq          ON node_version TYPE int READONLY;
DEFINE FIELD author_type  ON node_version TYPE string READONLY;
DEFINE FIELD author_id    ON node_version TYPE string READONLY;
DEFINE FIELD cert_id      ON node_version TYPE option<string> READONLY;
DEFINE FIELD signature    ON node_version TYPE string READONLY;
DEFINE FIELD created_at   ON node_version TYPE datetime VALUE time::now() READONLY;

DEFINE INDEX idx_node_version_node ON node_version FIELDS node_id, seq;

-- ── access_grant: who may use a node, and the key material to do so ──────────
-- Roles are read and write; the node's owner holds write on everything they own
-- without a grant. One row per (node, principal); a re-grant or a revoke updates
-- it in place, takes a new seq so the principal's next pull sees the change, and
-- points `log_index` at the access_log entry that made it. `facets` NONE grants
-- the whole node and its subtree; a facet list grants those facets of that node
-- only. `signature` is the signature of that log entry. `seq` is taken from the
-- change counter on create; `collection` and `owner_id` are copied from the node.
DEFINE TABLE access_grant SCHEMAFULL;
DEFINE FIELD node_id         ON access_grant TYPE string READONLY;
DEFINE FIELD collection      ON access_grant TYPE string
    VALUE (SELECT VALUE collection FROM ONLY type::record('node', $this.node_id));
DEFINE FIELD owner_id        ON access_grant TYPE string
    VALUE (SELECT VALUE owner_id FROM ONLY type::record('node', $this.node_id));
DEFINE FIELD principal_type  ON access_grant TYPE string READONLY
    ASSERT $value IN ["user", "install"];
DEFINE FIELD principal_id    ON access_grant TYPE string READONLY;
DEFINE FIELD role            ON access_grant TYPE string
    ASSERT $value IN ["read", "write"];
DEFINE FIELD facets          ON access_grant TYPE option<array<int>>;
DEFINE FIELD epoch           ON access_grant TYPE int;
DEFINE FIELD wrapped_keys    ON access_grant TYPE string;
DEFINE FIELD granted_by_type ON access_grant TYPE string ASSERT $value IN ["user", "install"];
DEFINE FIELD granted_by_id   ON access_grant TYPE string;
DEFINE FIELD cert_id         ON access_grant TYPE option<string>;
DEFINE FIELD signature       ON access_grant TYPE string;
DEFINE FIELD log_index       ON access_grant TYPE int;
DEFINE FIELD seq             ON access_grant TYPE int
    VALUE IF $before = NONE { fn::next_seq() } ELSE { $value };
DEFINE FIELD created_at      ON access_grant TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD revoked_at      ON access_grant TYPE option<datetime>;

DEFINE INDEX idx_access_grant_unique    ON access_grant FIELDS node_id, principal_type, principal_id UNIQUE;
DEFINE INDEX idx_access_grant_principal ON access_grant FIELDS principal_type, principal_id;
DEFINE INDEX idx_access_grant_seq       ON access_grant FIELDS seq;
DEFINE INDEX idx_access_grant_owner     ON access_grant FIELDS owner_id;
DEFINE INDEX idx_access_grant_actor     ON access_grant FIELDS granted_by_id;

-- ── access_log: the per-node hash chain of grants and revocations ────────────
-- Every grant and revoke is one entry, signed by the acting user's identity key
-- and chained to the previous entry by its hash. Entries are stored exactly as
-- submitted and never changed or deleted. (node_id, index) is unique, so two
-- writers cannot both extend the same head. `collection` and `node_ancestors`
-- are copied from the node so pulls can find the entries of visible nodes;
-- `seq` is taken from the change counter on create.
DEFINE TABLE access_log SCHEMAFULL;
DEFINE FIELD node_id          ON access_log TYPE string READONLY;
DEFINE FIELD index            ON access_log TYPE int READONLY;
DEFINE FIELD prev_hash        ON access_log TYPE string READONLY;
DEFINE FIELD entry_hash       ON access_log TYPE string READONLY;
DEFINE FIELD action           ON access_log TYPE string READONLY ASSERT $value IN ["grant", "revoke"];
DEFINE FIELD principal_type   ON access_log TYPE string READONLY;
DEFINE FIELD principal_id     ON access_log TYPE string READONLY;
DEFINE FIELD role             ON access_log TYPE string READONLY;
DEFINE FIELD facets           ON access_log TYPE option<array<int>> READONLY;
DEFINE FIELD epoch            ON access_log TYPE int READONLY;
DEFINE FIELD wrapped_keys_hash ON access_log TYPE string READONLY;
DEFINE FIELD actor_type       ON access_log TYPE string READONLY;
DEFINE FIELD actor_id         ON access_log TYPE string READONLY;
DEFINE FIELD cert_id          ON access_log TYPE option<string> READONLY;
DEFINE FIELD signature        ON access_log TYPE string READONLY;
DEFINE FIELD collection       ON access_log TYPE string READONLY
    VALUE (SELECT VALUE collection FROM ONLY type::record('node', $this.node_id));
DEFINE FIELD node_ancestors   ON access_log TYPE array<string> READONLY
    VALUE (SELECT VALUE ancestors FROM ONLY type::record('node', $this.node_id));
DEFINE FIELD owner_id         ON access_log TYPE string READONLY
    VALUE (SELECT VALUE owner_id FROM ONLY type::record('node', $this.node_id));
DEFINE FIELD seq              ON access_log TYPE int READONLY
    VALUE IF $before = NONE { fn::next_seq() } ELSE { $value };
DEFINE FIELD created_at       ON access_log TYPE datetime VALUE $before OR time::now() READONLY;

DEFINE INDEX idx_access_log_chain ON access_log FIELDS node_id, index UNIQUE;
DEFINE INDEX idx_access_log_seq   ON access_log FIELDS seq;

-- ── link: an unauthenticated share of a node's subtree ───────────────────────
-- The node key travels in the URL fragment and never reaches the server.
DEFINE TABLE link SCHEMAFULL;
DEFINE FIELD node_id    ON link TYPE string READONLY;
DEFINE FIELD created_by ON link TYPE string READONLY;
DEFINE FIELD created_at ON link TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD revoked_at ON link TYPE option<datetime>;

DEFINE INDEX idx_link_node ON link FIELDS node_id;

-- ── purge_horizon: per owner, the newest tombstone seq that has been purged ──
-- A cursor older than this may have missed a deletion; pull answers 410 and the
-- client resyncs from scratch. The record id is the owner's userId.
DEFINE TABLE purge_horizon SCHEMAFULL;
DEFINE FIELD user_id    ON purge_horizon TYPE string READONLY;
DEFINE FIELD seq        ON purge_horizon TYPE int DEFAULT 0;
DEFINE FIELD updated_at ON purge_horizon TYPE datetime VALUE time::now();

DEFINE INDEX idx_purge_horizon_user ON purge_horizon FIELDS user_id UNIQUE;

-- ── Shared transaction fragments ─────────────────────────────────────────────
-- Flags a node (and its subtree for a whole-node grant) so the owner's next vault
-- session rotates its key. Each touched node takes a new seq so the owner's pull
-- sees the flag.
DEFINE FUNCTION fn::flag_for_rotation($node_id: string, $whole_node: bool) {
    IF $whole_node {
        UPDATE node SET needs_rotation = true, seq = fn::next_seq()
            WHERE record::id(id) = $node_id OR $node_id IN ancestors;
    } ELSE {
        UPDATE type::record('node', $node_id) SET needs_rotation = true, seq = fn::next_seq();
    };
};

-- Whether the principal holds one of $roles at $node: as the user who owns it
-- (owners hold write; $roles is empty when the token's scopes forbid the
-- access), by a whole-node grant on an ancestor, or by any grant on the node
-- itself. $user_id is empty for installs, which own nothing.
DEFINE FUNCTION fn::holds_role_at($principal_type: string, $principal_id: string, $user_id: string,
        $node: object, $roles: array<string>) {
    LET $owns = $user_id != "" AND $node.owner_id = $user_id AND array::len($roles) > 0;
    RETURN $owns OR array::len((SELECT VALUE id FROM access_grant
        WHERE principal_type = $principal_type AND principal_id = $principal_id
        AND revoked_at = NONE AND role IN $roles
        AND ((facets = NONE AND node_id IN $node.ancestors) OR node_id = record::id($node.id)))) > 0;
};

-- Whether the principal holds one of $roles on the item $target_id through a
-- live shortcut: one that passes on such a role, at a place where the principal
-- holds it too.
DEFINE FUNCTION fn::reaches_through_shortcut($principal_type: string, $principal_id: string, $user_id: string,
        $target_id: string, $roles: array<string>) {
    LET $shortcuts = (SELECT * FROM node WHERE target_id = $target_id AND deleted = false AND target_role IN $roles);
    RETURN array::any($shortcuts, |$shortcut| fn::holds_role_at($principal_type, $principal_id, $user_id, $shortcut, $roles));
};
