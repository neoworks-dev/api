-- Per-contact calendar invite preferences. A directed edge in = the user setting
-- the preference, out = the other user it applies to. "block" drops that user's
-- invites silently; "auto_accept" turns their invites into already-accepted
-- attendance (the event shows immediately, no pending prompt). The absence of an
-- edge means the default behaviour (a pending invite). Modelled on `connection`.

DEFINE TABLE invite_policy SCHEMAFULL TYPE RELATION IN user OUT user;
DEFINE FIELD policy     ON invite_policy TYPE string
    ASSERT $value IN ["block", "auto_accept"];
DEFINE FIELD created_at ON invite_policy TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD updated_at ON invite_policy TYPE datetime VALUE time::now();

DEFINE INDEX idx_invite_policy_pair ON invite_policy FIELDS in, out UNIQUE;
DEFINE INDEX idx_invite_policy_in   ON invite_policy FIELDS in;
