-- ── asset: generic stored file (image / document) served by the assets service ──
-- Bytes live in object storage under `storage_key`; this row holds the metadata the
-- assets service uses to decide whether it may serve the object to the requester.
-- `visibility = "public"` is served to anyone; "private" requires the owner's token.
DEFINE TABLE asset SCHEMAFULL;
DEFINE FIELD storage_key  ON asset TYPE string                                   READONLY;
DEFINE FIELD mime         ON asset TYPE string;
DEFINE FIELD size         ON asset TYPE int;
DEFINE FIELD visibility   ON asset TYPE string
    ASSERT $value IN ["public", "private"]                       DEFAULT "private";
DEFINE FIELD owner        ON asset TYPE option<record<user>>                     READONLY;
DEFINE FIELD organization ON asset TYPE option<record<organization>>             READONLY;
DEFINE FIELD created_at   ON asset TYPE datetime VALUE time::now()               READONLY;

DEFINE INDEX idx_asset_owner ON asset FIELDS owner;
