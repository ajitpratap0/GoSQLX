SELECT * FROM users; -- Potential security issue
SELECT COUNT(*) FROM logs WHERE date > NOW() - INTERVAL '1 day';
