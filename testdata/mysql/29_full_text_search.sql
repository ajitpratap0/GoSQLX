-- FULLTEXT search (MySQL-specific)
-- Complexity: Medium
-- Tests: MATCH AGAINST for full-text search
SELECT id, title, content
FROM articles
WHERE MATCH(title, content) AGAINST('database performance' IN NATURAL LANGUAGE MODE);
