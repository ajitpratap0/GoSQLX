-- PostgreSQL DISTINCT ON clause
-- Complexity: Medium
-- Tests: DISTINCT ON (PostgreSQL-specific)
SELECT DISTINCT ON (user_id) user_id, created_at, status
FROM orders
ORDER BY user_id, created_at DESC;
