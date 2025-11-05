-- SQL Server OFFSET FETCH pagination
-- Complexity: Simple
-- Tests: OFFSET FETCH NEXT (SQL Server 2012+)
SELECT id, title, created_at
FROM posts
ORDER BY created_at DESC
OFFSET 20 ROWS
FETCH NEXT 10 ROWS ONLY;
