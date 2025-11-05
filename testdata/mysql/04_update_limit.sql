-- UPDATE with LIMIT (MySQL feature)
-- Complexity: Simple
-- Tests: UPDATE with LIMIT clause
UPDATE users SET last_login = NOW() WHERE active = 1 LIMIT 100;
