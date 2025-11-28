-- Oracle OFFSET FETCH (12c+)
-- Complexity: Simple
-- Tests: Modern Oracle pagination
SELECT id, name, created_at
FROM users
ORDER BY created_at DESC
OFFSET 20 ROWS
FETCH NEXT 10 ROWS ONLY;
