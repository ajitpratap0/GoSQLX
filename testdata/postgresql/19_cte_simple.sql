-- Simple Common Table Expression (CTE)
-- Complexity: Complex
-- Tests: WITH clause, CTE basic usage
WITH active_users AS (
    SELECT id, name, email FROM users WHERE active = true
)
SELECT au.name, COUNT(o.id) as order_count
FROM active_users au
LEFT JOIN orders o ON au.id = o.user_id
GROUP BY au.name
ORDER BY order_count DESC;
