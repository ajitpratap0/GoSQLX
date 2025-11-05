-- INNER JOIN with two tables
-- Complexity: Medium
-- Tests: INNER JOIN, table aliases, column selection
SELECT u.id, u.name, o.order_date, o.total
FROM users u
INNER JOIN orders o ON u.id = o.user_id
WHERE o.status = 'completed';
