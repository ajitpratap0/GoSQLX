-- LEFT JOIN with COUNT
-- Complexity: Medium
-- Tests: LEFT JOIN, COUNT aggregate, GROUP BY
SELECT
    u.name,
    COUNT(o.id) as order_count
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.id, u.name
HAVING order_count > 0;
