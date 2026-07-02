-- ── notification: in-app / push notification routed to a user's devices ──────
-- Created when a client (or Neoworks itself) sends a notification. The row backs
-- the authenticator's notification feed; delivery to devices is via push_token.
DEFINE TABLE notification SCHEMAFULL;
DEFINE FIELD user       ON notification TYPE record<user>          READONLY;
DEFINE FIELD title      ON notification TYPE string;
DEFINE FIELD body       ON notification TYPE string;
DEFINE FIELD url        ON notification TYPE option<string>;
DEFINE FIELD read       ON notification TYPE bool                  DEFAULT false;
DEFINE FIELD created_at ON notification TYPE datetime VALUE time::now() READONLY;

DEFINE INDEX idx_notification_user      ON notification COLUMNS user;
DEFINE INDEX idx_notification_user_read ON notification COLUMNS user, read;

-- ── org_invite: pending email invitation to join an organization ─────────────
-- Created by an org owner/admin. The recipient accepts via a tokenised link; on
-- accept a membership relation is created with the invite's role.
DEFINE TABLE org_invite SCHEMAFULL;
DEFINE FIELD organization ON org_invite TYPE record<organization>      READONLY;
DEFINE FIELD email        ON org_invite TYPE string
    ASSERT string::is_email($value)                                   READONLY;
DEFINE FIELD role         ON org_invite TYPE string
    ASSERT $value IN ["owner", "admin", "member", "billing"]          DEFAULT "member";
DEFINE FIELD token        ON org_invite TYPE string                   READONLY;
DEFINE FIELD status       ON org_invite TYPE string
    ASSERT $value IN ["pending", "accepted", "revoked", "expired"]    DEFAULT "pending";
DEFINE FIELD invited_by   ON org_invite TYPE option<record<user>>     READONLY;
DEFINE FIELD created_at   ON org_invite TYPE datetime VALUE time::now() READONLY;
DEFINE FIELD expires_at   ON org_invite TYPE datetime                 READONLY;

DEFINE INDEX idx_org_invite_token ON org_invite FIELDS token UNIQUE;
DEFINE INDEX idx_org_invite_org   ON org_invite FIELDS organization, email;
