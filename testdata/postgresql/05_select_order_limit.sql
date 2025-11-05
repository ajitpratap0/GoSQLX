-- SELECT with ORDER BY and LIMIT
-- Complexity: Simple
-- Tests: ORDER BY, LIMIT, OFFSET
SELECT id, name, created_at FROM posts ORDER BY created_at DESC LIMIT 10 OFFSET 20;
