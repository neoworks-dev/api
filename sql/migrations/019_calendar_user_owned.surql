-- Move the calendar from org-owned ("household") to user-owned. Calendars and
-- events now belong to an individual user (`owner`). Sharing is done per-event by
-- inviting participants who are neoworks users: an `attendance` edge (modelled on
-- `connection` / `membership`) records the invite and its accept state. The single
-- shared event then appears for the owner and any accepted attendee, and both may
-- edit it. Replaces the `organization` scoping from migration 011.

-- ── Calendars: organization → owner ──────────────────────────────────────────
-- Define owner permissively first so the backfill can write it, then tighten to
-- required + READONLY (DEFINE FIELD does not retro-validate existing rows).
DEFINE FIELD owner ON calendar TYPE option<record<user>>;
-- Best-effort backfill: attribute each calendar to the first member of its org.
UPDATE calendar SET owner = (SELECT VALUE in FROM membership WHERE out = $parent.organization LIMIT 1)[0] WHERE owner = NONE;
DEFINE FIELD OVERWRITE owner ON calendar TYPE record<user> READONLY;

REMOVE INDEX IF EXISTS idx_calendar_org ON calendar;
REMOVE FIELD IF EXISTS organization ON calendar;
DEFINE INDEX idx_calendar_owner ON calendar FIELDS owner;

-- ── Events: organization → owner ──────────────────────────────────────────────
DEFINE FIELD owner ON event TYPE option<record<user>>;
-- The creator becomes the owner.
UPDATE event SET owner = created_by WHERE owner = NONE AND created_by != NONE;
DEFINE FIELD OVERWRITE owner ON event TYPE record<user> READONLY;

REMOVE INDEX IF EXISTS idx_event_org       ON event;
REMOVE INDEX IF EXISTS idx_event_org_start ON event;
REMOVE INDEX IF EXISTS idx_event_uid       ON event;
REMOVE FIELD IF EXISTS organization        ON event;

DEFINE INDEX idx_event_owner       ON event FIELDS owner;
DEFINE INDEX idx_event_owner_start ON event FIELDS owner, start_time;
DEFINE INDEX idx_event_uid         ON event FIELDS owner, uid UNIQUE;

-- ── Attendance (event invitations / sharing) ──────────────────────────────────
-- A directed edge in = invited user, out = event. status flips to "accepted" when
-- the invitee accepts (event then shows on their calendar) or "declined".
DEFINE TABLE attendance SCHEMAFULL TYPE RELATION IN user OUT event;
DEFINE FIELD status     ON attendance TYPE string DEFAULT "pending"
    ASSERT $value IN ["pending", "accepted", "declined"];
DEFINE FIELD created_at ON attendance TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD updated_at ON attendance TYPE datetime VALUE time::now();

DEFINE INDEX idx_attendance_pair ON attendance FIELDS in, out UNIQUE;
DEFINE INDEX idx_attendance_in   ON attendance FIELDS in;
DEFINE INDEX idx_attendance_out  ON attendance FIELDS out;
