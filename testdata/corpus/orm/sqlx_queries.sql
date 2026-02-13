-- sqlx-style: Parameterized queries
SELECT id, name, email, created_at FROM users WHERE id = $1;

SELECT u.id, u.name, u.email, p.bio, p.avatar_url
FROM users u
INNER JOIN profiles p ON p.user_id = u.id
WHERE u.active = true AND u.created_at > $1
ORDER BY u.created_at DESC;

INSERT INTO users (name, email, age, created_at, updated_at)
VALUES ($1, $2, $3, NOW(), NOW());

UPDATE users SET name = $1, email = $2, updated_at = NOW() WHERE id = $3;

DELETE FROM sessions WHERE expires_at < NOW();

SELECT u.id, u.name, COUNT(o.id) AS order_count, COALESCE(SUM(o.total), 0) AS total_spent
FROM users u
LEFT JOIN orders o ON o.user_id = u.id AND o.status = 'completed'
WHERE u.created_at BETWEEN $1 AND $2
GROUP BY u.id, u.name
HAVING COUNT(o.id) > 0
ORDER BY total_spent DESC;
