-- User-to-user connections with consent-based profile sharing.
--
-- A `connection` is a directed request edge (in = requester, out = addressee)
-- that becomes a mutual connection when status flips to "accepted"; it is queried
-- symmetrically from either endpoint. A `sharing_grant` (in = owner, out = viewer)
-- lists extra profile fields the owner consents to share beyond their name, which
-- is always visible between accepted connections. Modelled on `membership` (002).

-- ── Connections ───────────────────────────────────────────────────────────────
DEFINE TABLE connection SCHEMAFULL TYPE RELATION IN user OUT user;
DEFINE FIELD status     ON connection TYPE string DEFAULT "pending"
    ASSERT $value IN ["pending", "accepted", "blocked"];
DEFINE FIELD created_at ON connection TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD updated_at ON connection TYPE datetime VALUE time::now();

-- One edge per ordered pair; reverse-direction duplicates are guarded in Go.
DEFINE INDEX idx_connection_pair ON connection FIELDS in, out UNIQUE;
DEFINE INDEX idx_connection_in   ON connection FIELDS in;
DEFINE INDEX idx_connection_out  ON connection FIELDS out;

-- ── Sharing grants (field-level consent) ──────────────────────────────────────
DEFINE TABLE sharing_grant SCHEMAFULL TYPE RELATION IN user OUT user;
DEFINE FIELD fields     ON sharing_grant TYPE array<string> DEFAULT []
    ASSERT $value ALLINSIDE ["email", "phone", "avatar_url"];
DEFINE FIELD created_at ON sharing_grant TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD updated_at ON sharing_grant TYPE datetime VALUE time::now();

DEFINE INDEX idx_sharing_grant_pair ON sharing_grant FIELDS in, out UNIQUE;
