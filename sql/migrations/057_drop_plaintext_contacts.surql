-- ── STAGED, NOT YET APPLIED ───────────────────────────────────────────────────
-- Drops the legacy plaintext contact tables after the E2EE cutover. Contacts
-- live in `contact_item` envelopes (migration 054); mutations on the plaintext
-- surface are already rejected (gql/resolvers/contacts_helpers.go).
--
-- Do NOT move this into sql/migrations/ until every device has run the client
-- migrator (apps/contacts src/lib/contacts/migrate.ts) — the read surface is the
-- migration source. When promoting: renumber to the next free version, and in
-- the same change delete the plaintext code paths (storage/database/contact.go,
-- contact_filter.go, gql/resolvers/Contacts.resolvers.go + contacts_helpers.go,
-- schema/Contacts.graphql, SDK resources/contacts.ts) and regenerate gqlgen.
-- No other table references record<contact> (verified 2026-07-28).

REMOVE TABLE IF EXISTS related;
REMOVE TABLE IF EXISTS member;
REMOVE TABLE IF EXISTS contact_version;
REMOVE TABLE IF EXISTS contact;   -- drops idx_contact_fts with it
REMOVE ANALYZER IF EXISTS contact_text;
