SELECT
  u.name,
  u.email,
  COUNT(o.id) AS order_count,
  SUM(o.total) AS lifetime_value
FROM users u
LEFT JOIN orders o ON o.user_id = u.id
WHERE u.created_at > '2024-01-01'
GROUP BY u.name, u.email
HAVING COUNT(o.id) > 5
ORDER BY lifetime_value DESC
LIMIT 20;
