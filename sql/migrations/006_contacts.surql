-- Full vCard 4.0 (RFC 6350) contact model on the versioned schema method
-- (contact / contact_version / shared derived_from from migration 005). Adds
-- soft-delete (deleted), archive (archived) and favorite flags, plus graph
-- relations for vCard RELATED and MEMBER.
--
-- Multi-valued vCard properties (emails, phones, addresses, …) are stored as
-- whole-field FLEXIBLE arrays of objects, with each element object also marked
-- FLEXIBLE (FLEXIBLE on an array field does not propagate to its elements;
-- SurrealDB otherwise auto-defines a strict `[*] TYPE object` rule that rejects
-- nested keys). PHOTO/LOGO/SOUND/KEY are references into the encrypted media
-- handler, never inlined base64. Absent optional fields are omitted from SET by
-- the Go layer so they default to NONE (see apps/api/CLAUDE.md).

-- ── Current state ─────────────────────────────────────────────────────────────
DEFINE TABLE contact SCHEMAFULL;

DEFINE FIELD user    ON contact TYPE record<user> READONLY;
DEFINE FIELD version ON contact TYPE record<contact_version>;

-- vCard general / identification.
DEFINE FIELD uid          ON contact TYPE string;
DEFINE FIELD kind         ON contact TYPE string DEFAULT 'individual'
    ASSERT $value IN ['individual', 'group', 'org', 'location'];
DEFINE FIELD formatted_name ON contact TYPE string;                       -- FN (required)
DEFINE FIELD name         ON contact TYPE option<object> FLEXIBLE;        -- N {family, given, additional[], prefixes[], suffixes[]}
DEFINE FIELD nicknames    ON contact TYPE option<array<string>>;         -- NICKNAME
DEFINE FIELD birthday     ON contact TYPE option<string>;                -- BDAY
DEFINE FIELD anniversary  ON contact TYPE option<string>;                -- ANNIVERSARY
DEFINE FIELD gender       ON contact TYPE option<object> FLEXIBLE;       -- GENDER {sex, identity}

-- Communications (each entry: {value, types[], pref, label}).
DEFINE FIELD emails    ON contact TYPE option<array<object>> FLEXIBLE;   -- EMAIL
DEFINE FIELD phones    ON contact TYPE option<array<object>> FLEXIBLE;   -- TEL
DEFINE FIELD impps     ON contact TYPE option<array<object>> FLEXIBLE;   -- IMPP
DEFINE FIELD languages ON contact TYPE option<array<object>> FLEXIBLE;   -- LANG {value, pref}

-- Delivery addressing (ADR).
DEFINE FIELD addresses ON contact TYPE option<array<object>> FLEXIBLE;   -- {types[], pref, label, po_box, ext, street, locality, region, postal_code, country}

-- Organizational.
DEFINE FIELD organizations ON contact TYPE option<array<object>> FLEXIBLE; -- ORG {name, units[]}
DEFINE FIELD title ON contact TYPE option<string>;                       -- TITLE
DEFINE FIELD role  ON contact TYPE option<string>;                       -- ROLE

-- Geographical.
DEFINE FIELD timezone ON contact TYPE option<string>;                    -- TZ
DEFINE FIELD geo      ON contact TYPE option<object> FLEXIBLE;           -- GEO {lat, lng}

-- Explanatory.
DEFINE FIELD categories ON contact TYPE option<array<string>>;           -- CATEGORIES (tags)
DEFINE FIELD notes      ON contact TYPE option<array<string>>;           -- NOTE
DEFINE FIELD urls       ON contact TYPE option<array<object>> FLEXIBLE;  -- URL {value, types[], pref}
DEFINE FIELD source     ON contact TYPE option<string>;                  -- SOURCE
DEFINE FIELD prodid     ON contact TYPE option<string>;                  -- PRODID

-- Calendar.
DEFINE FIELD fburl     ON contact TYPE option<string>;                   -- FBURL
DEFINE FIELD caluri    ON contact TYPE option<string>;                   -- CALURI
DEFINE FIELD caladruri ON contact TYPE option<string>;                   -- CALADRURI

-- Media & security — encrypted media references, never inline base64.
DEFINE FIELD photo ON contact TYPE option<record<media>>;                -- PHOTO
DEFINE FIELD logo  ON contact TYPE option<record<media>>;                -- LOGO
DEFINE FIELD sound ON contact TYPE option<record<media>>;                -- SOUND
DEFINE FIELD key   ON contact TYPE option<record<media>>;                -- KEY

-- Beyond vCard: arbitrary labelled fields (the X- gap), flags.
DEFINE FIELD custom_fields ON contact TYPE option<array<object>> FLEXIBLE; -- {label, value}
DEFINE FIELD favorite ON contact TYPE bool DEFAULT false;
DEFINE FIELD archived ON contact TYPE bool DEFAULT false;
DEFINE FIELD deleted  ON contact TYPE bool DEFAULT false;

DEFINE FIELD created_at ON contact TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD updated_at ON contact TYPE datetime VALUE time::now();

DEFINE INDEX idx_contact_user     ON contact FIELDS user;
DEFINE INDEX idx_contact_user_uid ON contact FIELDS user, uid UNIQUE;
DEFINE INDEX idx_contact_deleted  ON contact FIELDS user, deleted;

-- ── Append-only history ───────────────────────────────────────────────────────
-- Mirrors every data field as READONLY; rows are never mutated after insert.
DEFINE TABLE contact_version SCHEMAFULL;

DEFINE FIELD contact_id ON contact_version TYPE record<contact> READONLY;
DEFINE FIELD user       ON contact_version TYPE record<user>    READONLY;

DEFINE FIELD uid            ON contact_version TYPE string                 READONLY;
DEFINE FIELD kind           ON contact_version TYPE string DEFAULT 'individual' READONLY;
DEFINE FIELD formatted_name ON contact_version TYPE string                 READONLY;
DEFINE FIELD name           ON contact_version TYPE option<object> FLEXIBLE READONLY;
DEFINE FIELD nicknames      ON contact_version TYPE option<array<string>>  READONLY;
DEFINE FIELD birthday       ON contact_version TYPE option<string>         READONLY;
DEFINE FIELD anniversary    ON contact_version TYPE option<string>         READONLY;
DEFINE FIELD gender         ON contact_version TYPE option<object> FLEXIBLE READONLY;
DEFINE FIELD emails         ON contact_version TYPE option<array<object>> FLEXIBLE READONLY;
DEFINE FIELD phones         ON contact_version TYPE option<array<object>> FLEXIBLE READONLY;
DEFINE FIELD impps          ON contact_version TYPE option<array<object>> FLEXIBLE READONLY;
DEFINE FIELD languages      ON contact_version TYPE option<array<object>> FLEXIBLE READONLY;
DEFINE FIELD addresses      ON contact_version TYPE option<array<object>> FLEXIBLE READONLY;
DEFINE FIELD organizations  ON contact_version TYPE option<array<object>> FLEXIBLE READONLY;
DEFINE FIELD title          ON contact_version TYPE option<string>         READONLY;
DEFINE FIELD role           ON contact_version TYPE option<string>         READONLY;
DEFINE FIELD timezone       ON contact_version TYPE option<string>         READONLY;
DEFINE FIELD geo            ON contact_version TYPE option<object> FLEXIBLE READONLY;
DEFINE FIELD categories     ON contact_version TYPE option<array<string>>  READONLY;
DEFINE FIELD notes          ON contact_version TYPE option<array<string>>  READONLY;
DEFINE FIELD urls           ON contact_version TYPE option<array<object>> FLEXIBLE READONLY;
DEFINE FIELD source         ON contact_version TYPE option<string>         READONLY;
DEFINE FIELD prodid         ON contact_version TYPE option<string>         READONLY;
DEFINE FIELD fburl          ON contact_version TYPE option<string>         READONLY;
DEFINE FIELD caluri         ON contact_version TYPE option<string>         READONLY;
DEFINE FIELD caladruri      ON contact_version TYPE option<string>         READONLY;
DEFINE FIELD photo          ON contact_version TYPE option<record<media>>  READONLY;
DEFINE FIELD logo           ON contact_version TYPE option<record<media>>  READONLY;
DEFINE FIELD sound          ON contact_version TYPE option<record<media>>  READONLY;
DEFINE FIELD key            ON contact_version TYPE option<record<media>>  READONLY;
DEFINE FIELD custom_fields  ON contact_version TYPE option<array<object>> FLEXIBLE READONLY;
DEFINE FIELD favorite       ON contact_version TYPE bool DEFAULT false     READONLY;
DEFINE FIELD archived       ON contact_version TYPE bool DEFAULT false     READONLY;
DEFINE FIELD deleted        ON contact_version TYPE bool DEFAULT false     READONLY;

DEFINE FIELD created_at ON contact_version TYPE datetime VALUE time::now() READONLY;

DEFINE INDEX idx_contact_version_contact ON contact_version FIELDS contact_id;

-- ── Graph relations (vCard RELATED / MEMBER) ──────────────────────────────────
-- Contact-to-contact links, traversable both directions. URI-based RELATED that
-- doesn't point at a known contact is kept in the embedded `urls`/custom fields.
DEFINE TABLE related SCHEMAFULL TYPE RELATION IN contact OUT contact;
DEFINE FIELD types ON related TYPE option<array<string>>;                 -- e.g. spouse, child, colleague
DEFINE FIELD pref  ON related TYPE option<int>;

-- Group membership: a KIND=group contact RELATEs to each member contact.
DEFINE TABLE member SCHEMAFULL TYPE RELATION IN contact OUT contact;

-- ── array<object> element flexibility (see header) ────────────────────────────
DEFINE FIELD OVERWRITE emails[*]        ON contact TYPE object FLEXIBLE;
DEFINE FIELD OVERWRITE phones[*]        ON contact TYPE object FLEXIBLE;
DEFINE FIELD OVERWRITE impps[*]         ON contact TYPE object FLEXIBLE;
DEFINE FIELD OVERWRITE languages[*]     ON contact TYPE object FLEXIBLE;
DEFINE FIELD OVERWRITE addresses[*]     ON contact TYPE object FLEXIBLE;
DEFINE FIELD OVERWRITE organizations[*] ON contact TYPE object FLEXIBLE;
DEFINE FIELD OVERWRITE urls[*]          ON contact TYPE object FLEXIBLE;
DEFINE FIELD OVERWRITE custom_fields[*] ON contact TYPE object FLEXIBLE;

DEFINE FIELD OVERWRITE emails[*]        ON contact_version TYPE object FLEXIBLE;
DEFINE FIELD OVERWRITE phones[*]        ON contact_version TYPE object FLEXIBLE;
DEFINE FIELD OVERWRITE impps[*]         ON contact_version TYPE object FLEXIBLE;
DEFINE FIELD OVERWRITE languages[*]     ON contact_version TYPE object FLEXIBLE;
DEFINE FIELD OVERWRITE addresses[*]     ON contact_version TYPE object FLEXIBLE;
DEFINE FIELD OVERWRITE organizations[*] ON contact_version TYPE object FLEXIBLE;
DEFINE FIELD OVERWRITE urls[*]          ON contact_version TYPE object FLEXIBLE;
DEFINE FIELD OVERWRITE custom_fields[*] ON contact_version TYPE object FLEXIBLE;
