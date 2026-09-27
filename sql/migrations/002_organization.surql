-- ── organization: a larger entity that owns clients and is billed for their usage ──
-- An organization is a separate billing identity from any user. The org owner's
-- personal account is never charged for org usage; the org pays via its own billing.
DEFINE TABLE organization SCHEMAFULL;
DEFINE FIELD name          ON organization TYPE string;
DEFINE FIELD slug          ON organization TYPE string;  -- the `organization` token used in scopes (e.g. "org_123")
DEFINE FIELD logo          ON organization TYPE option<record<blob>>;
DEFINE FIELD logo_url      ON organization TYPE option<string>;  -- public URL served by the api's asset listener
DEFINE FIELD description   ON organization TYPE option<string>;  -- free-text shown in the dashboard
DEFINE FIELD billing_email ON organization TYPE option<string>;
DEFINE FIELD created_at    ON organization TYPE datetime VALUE time::now() READONLY;
DEFINE FIELD updated_at    ON organization TYPE datetime VALUE time::now();
DEFINE FIELD deleted_at    ON organization TYPE option<datetime>;

DEFINE INDEX idx_org_slug    ON organization FIELDS slug UNIQUE;
DEFINE INDEX idx_org_deleted ON organization FIELDS deleted_at;

-- ── membership: user ↔ organization, many-to-many, carries a role ──
-- A user can belong to any number of organizations.
DEFINE TABLE membership SCHEMAFULL TYPE RELATION IN user OUT organization;
DEFINE FIELD role       ON membership TYPE string DEFAULT "member"
    ASSERT $value IN ["owner", "admin", "member", "billing"];
DEFINE FIELD created_at ON membership TYPE datetime VALUE time::now() READONLY;

DEFINE INDEX idx_membership_unique ON membership FIELDS in, out UNIQUE;

-- First-party organization that owns Neoworks' own internal clients (seeded below).
CREATE organization:neoworks CONTENT {
    name:          "Neoworks",
    slug:          "neoworks",
    billing_email: "billing@neoworks.dev"
};
