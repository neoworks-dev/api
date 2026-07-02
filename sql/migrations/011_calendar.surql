-- Shared family calendar, jsCalendar (RFC 8984) aligned. Calendars and events are
-- owned by an organization (the "household"); any member of the org may read/write
-- them — the same org-scoped ownership model that `client` uses.
--
-- Nested jsCalendar data (participants, locations, alerts, links, recurrence rules,
-- …) is stored as whole-field FLEXIBLE objects/arrays. For array<object> fields the
-- element objects are also marked FLEXIBLE (FLEXIBLE on an array does not propagate
-- to its elements; SurrealDB otherwise auto-defines a strict `[*] TYPE object` rule
-- that rejects nested keys). Absent optional fields are omitted from SET by the Go
-- layer so they default to NONE (see apps/api/CLAUDE.md).

-- ── Calendars (grouping, carries colour) ──────────────────────────────────────
DEFINE TABLE calendar SCHEMAFULL;
DEFINE FIELD organization ON calendar TYPE record<organization> READONLY;
DEFINE FIELD name         ON calendar TYPE string;
DEFINE FIELD color        ON calendar TYPE string
    ASSERT $value IN ["green", "red", "amber", "blue", "violet", "pink", "neutral"];
DEFINE FIELD is_default   ON calendar TYPE bool DEFAULT false;
DEFINE FIELD created_at   ON calendar TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD updated_at   ON calendar TYPE datetime VALUE time::now();

DEFINE INDEX idx_calendar_org ON calendar FIELDS organization;

-- ── Events (jsCalendar Event) ─────────────────────────────────────────────────
DEFINE TABLE event SCHEMAFULL;
DEFINE FIELD organization ON event TYPE record<organization>      READONLY;
DEFINE FIELD created_by   ON event TYPE option<record<user>>;
DEFINE FIELD calendar     ON event TYPE option<record<calendar>>;

-- jsCalendar metadata.
DEFINE FIELD uid          ON event TYPE string;
DEFINE FIELD title        ON event TYPE string;
DEFINE FIELD description  ON event TYPE option<string>;

-- Timing: jsCalendar uses a zoneless LocalDateTime `start` + ISO-8601 `duration`
-- + IANA `time_zone` (null = floating). `show_without_time` is the all-day flag.
DEFINE FIELD start             ON event TYPE string;
DEFINE FIELD duration          ON event TYPE option<string>;
DEFINE FIELD time_zone         ON event TYPE option<string>;
DEFINE FIELD show_without_time ON event TYPE bool DEFAULT false;

-- Derived absolute UTC bounds, maintained by the Go layer for range queries and
-- the start index. Not part of the jsCalendar surface.
DEFINE FIELD start_time   ON event TYPE datetime;
DEFINE FIELD end_time     ON event TYPE datetime;

-- jsCalendar enums and scalars.
DEFINE FIELD status          ON event TYPE option<string>
    ASSERT $value IN ["confirmed", "cancelled", "tentative"];
DEFINE FIELD free_busy_status ON event TYPE option<string>
    ASSERT $value IN ["free", "busy"];
DEFINE FIELD privacy         ON event TYPE option<string>
    ASSERT $value IN ["public", "private", "secret"];
DEFINE FIELD priority        ON event TYPE option<int>;
DEFINE FIELD color           ON event TYPE option<string>;
DEFINE FIELD sequence        ON event TYPE option<int>;
DEFINE FIELD keywords        ON event TYPE option<array<string>>;

-- jsCalendar collections, keyed maps / arrays kept schemaless inside.
DEFINE FIELD participants              ON event TYPE option<object> FLEXIBLE;
DEFINE FIELD locations                 ON event TYPE option<object> FLEXIBLE;
DEFINE FIELD virtual_locations         ON event TYPE option<object> FLEXIBLE;
DEFINE FIELD alerts                    ON event TYPE option<object> FLEXIBLE;
DEFINE FIELD links                     ON event TYPE option<object> FLEXIBLE;
DEFINE FIELD related_to                ON event TYPE option<object> FLEXIBLE;
DEFINE FIELD localizations             ON event TYPE option<object> FLEXIBLE;
DEFINE FIELD recurrence_overrides      ON event TYPE option<object> FLEXIBLE;
DEFINE FIELD recurrence_rules          ON event TYPE option<array<object>> FLEXIBLE;
DEFINE FIELD excluded_recurrence_rules ON event TYPE option<array<object>> FLEXIBLE;

DEFINE FIELD created_at   ON event TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD updated_at   ON event TYPE datetime VALUE time::now();

DEFINE INDEX idx_event_org       ON event FIELDS organization;
DEFINE INDEX idx_event_org_start ON event FIELDS organization, start_time;
DEFINE INDEX idx_event_uid       ON event FIELDS organization, uid UNIQUE;

-- Recurrence rule array elements stored verbatim (see header).
DEFINE FIELD OVERWRITE recurrence_rules[*]          ON event TYPE object FLEXIBLE;
DEFINE FIELD OVERWRITE excluded_recurrence_rules[*] ON event TYPE object FLEXIBLE;
