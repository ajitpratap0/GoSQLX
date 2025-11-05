-- INSERT ON DUPLICATE KEY UPDATE (MySQL-specific)
-- Complexity: Medium
-- Tests: MySQL upsert syntax
INSERT INTO user_stats (user_id, login_count, last_login)
VALUES (123, 1, NOW())
ON DUPLICATE KEY UPDATE
    login_count = login_count + 1,
    last_login = NOW();
