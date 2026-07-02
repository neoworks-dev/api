-- BM25 FULLTEXT index on contact.formatted_name, using the contact_text analyzer
-- from the previous migration. Enables the `search` filter operator (the `@@`
-- match operator) plus search::score / search::highlight.
--
-- SurrealDB 3.0 renamed the index keyword SEARCH → FULLTEXT.
DEFINE INDEX IF NOT EXISTS idx_contact_fts
    ON contact
    FIELDS formatted_name
    FULLTEXT ANALYZER contact_text BM25 HIGHLIGHTS;
