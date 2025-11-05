-- DELETE with LIMIT (MySQL feature)
-- Complexity: Simple
-- Tests: DELETE with LIMIT clause
DELETE FROM logs WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY) LIMIT 1000;
