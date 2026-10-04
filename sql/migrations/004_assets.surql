-- ── asset: public or owner-private plaintext file served by the assets listener ─
-- Bytes live in object storage under `storage_key`. These are not end-to-end
-- encrypted (avatars, logos); encrypted user files are nodes with blobs.
DEFINE TABLE asset SCHEMAFULL;
DEFINE FIELD storage_key ON asset TYPE string READONLY;
DEFINE FIELD mime        ON asset TYPE string;
DEFINE FIELD size        ON asset TYPE int;
DEFINE FIELD visibility  ON asset TYPE string
    ASSERT $value IN ["public", "private"] DEFAULT "private";
DEFINE FIELD owner       ON asset TYPE option<record<user>> READONLY;
DEFINE FIELD created_at  ON asset TYPE datetime VALUE time::now() READONLY;

DEFINE INDEX idx_asset_owner ON asset FIELDS owner;
