-- Give the OpenSchema registry client a secret WITHOUT making it non-public.
-- The client stays public so user logins keep using PKCE (the site's server-side
-- code exchange is unchanged). The secret is used only for the client_credentials
-- grant: the site's server mints a user-less org token to publish org-owned
-- schema rows on behalf of users ("users submit to the org's server, the org
-- writes to the DB"). Plaintext dev secret: openschema-dev-secret — set it in the
-- apps/openschema env as OPENSCHEMA_CLIENT_SECRET (real secret per environment).
-- Also register the CLI's loopback redirect so `openschema login` can complete a
-- PKCE flow on the user's machine (exact-match validated, so it must be seeded).
UPDATE client:openschema SET
    secret_hash = "$2b$10$3iIZbp7UnS/hR0DNw/IPfOxi9dYXTOx0U/KXJUWuMP7xhk/FitNQm",
    redirect_uris += "http://127.0.0.1:8976/callback";
