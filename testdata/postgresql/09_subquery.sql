-- Subquery in WHERE clause
-- Complexity: Medium
-- Tests: Subquery, IN operator
SELECT name, email
FROM users
WHERE id IN (
    SELECT user_id FROM orders WHERE total > 1000
);
