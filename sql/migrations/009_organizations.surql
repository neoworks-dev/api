-- ── handle: the one namespace of people and organizations ─────────────────────
-- The record id is the handle itself, so a handle exists once. Rows are never
-- deleted: a handle stays taken after its owner is gone, because collection
-- paths like `@acme/recipes` live in stored encrypted data.
DEFINE TABLE handle SCHEMAFULL;
DEFINE FIELD kind         ON handle TYPE string READONLY ASSERT $value IN ['user', 'organization'];
DEFINE FIELD user         ON handle TYPE option<record<user>> READONLY;
DEFINE FIELD organization ON handle TYPE option<record<organization>> READONLY;
DEFINE FIELD claimed_at   ON handle TYPE datetime VALUE $before OR time::now() READONLY;

-- ── organization: publishes apps and schemas under its handle ────────────────
-- The record id is the organization's handle. Archived organizations keep their
-- handle and published schemas; nobody can publish into them.
DEFINE TABLE organization SCHEMAFULL;
DEFINE FIELD display_name ON organization TYPE string ASSERT string::len($value) > 0 AND string::len($value) <= 100;
DEFINE FIELD created_by   ON organization TYPE option<record<user>> READONLY;
DEFINE FIELD archived_at  ON organization TYPE option<datetime>;
-- Set by a Neoworks administrator after review (#35, #36).
DEFINE FIELD verified_at  ON organization TYPE option<datetime>;
DEFINE FIELD created_at   ON organization TYPE datetime VALUE $before OR time::now() READONLY;

-- ── organization_member: a user's membership and permission grants ───────────
-- A grant is a permission with an optional `app` (OAuth client id); without one
-- it covers the whole organization. Permission rules live in `ownership/`.
DEFINE TABLE organization_member SCHEMAFULL;
DEFINE FIELD organization      ON organization_member TYPE record<organization> READONLY;
DEFINE FIELD user              ON organization_member TYPE record<user> READONLY;
DEFINE FIELD grants            ON organization_member TYPE array<object> DEFAULT [];
DEFINE FIELD grants[*].permission ON organization_member TYPE string;
DEFINE FIELD grants[*].app     ON organization_member TYPE option<string>;
DEFINE FIELD joined_at         ON organization_member TYPE datetime VALUE $before OR time::now() READONLY;

DEFINE INDEX organization_member_unique ON organization_member FIELDS organization, user UNIQUE;
DEFINE INDEX organization_member_user   ON organization_member FIELDS user;

-- ── organization_invitation: an offer of membership with grants ──────────────
-- Addressed to an email address or, through a contact code, to a user. The row
-- is deleted when the invitation is accepted, declined or revoked.
DEFINE TABLE organization_invitation SCHEMAFULL;
DEFINE FIELD organization      ON organization_invitation TYPE record<organization> READONLY;
DEFINE FIELD email             ON organization_invitation TYPE option<string> READONLY;
DEFINE FIELD contact_code      ON organization_invitation TYPE option<string> READONLY;
DEFINE FIELD invitee           ON organization_invitation TYPE option<record<user>> READONLY;
DEFINE FIELD grants            ON organization_invitation TYPE array<object>;
DEFINE FIELD grants[*].permission ON organization_invitation TYPE string;
DEFINE FIELD grants[*].app     ON organization_invitation TYPE option<string>;
DEFINE FIELD invited_by        ON organization_invitation TYPE record<user> READONLY;
DEFINE FIELD created_at        ON organization_invitation TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD expires_at        ON organization_invitation TYPE datetime READONLY;

DEFINE INDEX organization_invitation_organization ON organization_invitation FIELDS organization;
DEFINE INDEX organization_invitation_email        ON organization_invitation FIELDS email;
DEFINE INDEX organization_invitation_invitee      ON organization_invitation FIELDS invitee;

-- ── organization_audit: security-relevant actions, append-only ───────────────
DEFINE TABLE organization_audit SCHEMAFULL;
DEFINE FIELD organization ON organization_audit TYPE record<organization> READONLY;
-- NONE for actions the system takes itself, such as revoking a domain that
-- stopped verifying.
DEFINE FIELD actor        ON organization_audit TYPE option<record<user>> READONLY;
DEFINE FIELD action       ON organization_audit TYPE string READONLY;
DEFINE FIELD target_kind  ON organization_audit TYPE string READONLY;
DEFINE FIELD target_id    ON organization_audit TYPE string READONLY;
DEFINE FIELD target_label ON organization_audit TYPE string READONLY;
DEFINE FIELD details      ON organization_audit TYPE object FLEXIBLE DEFAULT {} READONLY;
DEFINE FIELD at           ON organization_audit TYPE datetime VALUE $before OR time::now() READONLY;

DEFINE INDEX organization_audit_at ON organization_audit FIELDS organization, at;

-- ── Neoworks: the first-party organization, owner of the `neoworks` handle ───
CREATE organization:neoworks SET display_name = 'Neoworks';
CREATE handle:neoworks SET kind = 'organization', organization = organization:neoworks;
