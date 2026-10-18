SELECT u.id, u.name, count(o.id) AS orders
FROM users u
INNER JOIN orders o ON o.user_id = u.id
WHERE u.active = true
GROUP BY u.id, u.name
HAVING count(o.id) > 5
ORDER BY orders DESC
LIMIT 10
