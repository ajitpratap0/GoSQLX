-- INNER JOIN with MySQL syntax
-- Complexity: Medium
-- Tests: INNER JOIN, table aliases
SELECT
    u.id,
    u.name,
    o.order_date,
    o.total
FROM users u
INNER JOIN orders o ON u.id = o.user_id
WHERE o.status = 'completed'
ORDER BY o.order_date DESC;
