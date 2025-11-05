-- NOT EXISTS subquery
-- Complexity: Medium
-- Tests: NOT EXISTS for anti-join pattern
SELECT u.name, u.email
FROM users u
WHERE NOT EXISTS (
    SELECT 1 FROM orders o WHERE o.user_id = u.id
);
