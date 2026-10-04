-- ── notification: in-app / push notification routed to a user's devices ──────
-- Backs the authenticator's notification feed; push delivery uses push_token.
DEFINE TABLE notification SCHEMAFULL;
DEFINE FIELD user       ON notification TYPE record<user> READONLY;
DEFINE FIELD title      ON notification TYPE string;
DEFINE FIELD body       ON notification TYPE string;
DEFINE FIELD url        ON notification TYPE option<string>;
DEFINE FIELD read       ON notification TYPE bool DEFAULT false;
DEFINE FIELD created_at ON notification TYPE datetime VALUE time::now() READONLY;

DEFINE INDEX idx_notification_user      ON notification COLUMNS user;
DEFINE INDEX idx_notification_user_read ON notification COLUMNS user, read;
