DEFINE TABLE user SCHEMAFULL;
DEFINE FIELD email      ON user TYPE string;
DEFINE FIELD name       ON user TYPE string;
DEFINE FIELD created_at ON user TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD updated_at ON user TYPE datetime VALUE time::now();

DEFINE INDEX idx_user_email ON user FIELDS email UNIQUE;

-- current state
DEFINE TABLE contact SCHEMAFULL;
DEFINE FIELD user       ON contact TYPE record<user>          READONLY;
DEFINE FIELD email      ON contact TYPE string;
DEFINE FIELD phone      ON contact TYPE option<string>;
DEFINE FIELD name       ON contact TYPE string;
DEFINE FIELD created_at ON contact TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD updated_at ON contact TYPE datetime VALUE time::now();
DEFINE FIELD version    ON contact TYPE record<contact_version>;

DEFINE INDEX idx_contact_user  ON contact FIELDS user;
DEFINE INDEX idx_contact_email ON contact FIELDS email;

-- append-only history
DEFINE TABLE contact_version SCHEMAFULL;
DEFINE FIELD contact_id ON contact_version TYPE record<contact> READONLY;
DEFINE FIELD user       ON contact_version TYPE record<user>    READONLY;
DEFINE FIELD email      ON contact_version TYPE string          READONLY;
DEFINE FIELD phone      ON contact_version TYPE option<string>  READONLY;
DEFINE FIELD name       ON contact_version TYPE string          READONLY;
DEFINE FIELD created_at ON contact_version TYPE datetime VALUE time::now() READONLY;

DEFINE INDEX idx_contact_version_contact ON contact_version FIELDS contact_id;

-- graph relation for ancestry traversal
DEFINE TABLE derived_from SCHEMAFULL TYPE RELATION IN contact_version OUT contact_version;
