SELECT id, name, email
FROM users
WHERE active = true
ORDER BY created_at DESC;
