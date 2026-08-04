-- Shared full-text analyzer, used by the memory and file indexes (017, 025).
-- An analyzer is not visible to an index created in the same transaction (the
-- migrate runner wraps each file in one), so any index using it must live in a
-- later migration than this one.
--
-- Tokenizers: blank (whitespace) + class (letter/digit/punct boundaries).
-- Filters: lowercase + ascii (fold diacritics) + snowball(english) (stemming).
DEFINE ANALYZER IF NOT EXISTS contact_text
    TOKENIZERS blank, class
    FILTERS lowercase, ascii, snowball(english);
