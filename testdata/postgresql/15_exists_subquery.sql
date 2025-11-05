-- EXISTS subquery
-- Complexity: Medium
-- Tests: EXISTS, correlated subquery
SELECT u.name, u.email
FROM users u
WHERE EXISTS (
    SELECT 1 FROM orders o WHERE o.user_id = u.id AND o.total > 500
);
