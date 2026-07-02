-- Full-text search analyzer for contacts. The matching FULLTEXT index is defined
-- in the next migration — a newly-defined analyzer is not visible to an index
-- created in the same transaction (the migrate runner wraps each file in one), so
-- they must land in separate migrations.
--
-- Tokenizers: blank (whitespace) + class (letter/digit/punct boundaries).
-- Filters: lowercase + ascii (fold diacritics) + snowball(english) (stemming).
DEFINE ANALYZER IF NOT EXISTS contact_text
    TOKENIZERS blank, class
    FILTERS lowercase, ascii, snowball(english);
