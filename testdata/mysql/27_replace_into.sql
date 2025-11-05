-- REPLACE INTO (MySQL-specific)
-- Complexity: Simple
-- Tests: REPLACE statement
REPLACE INTO cache (key_name, value, expires_at)
VALUES ('user:123', 'cached_data', DATE_ADD(NOW(), INTERVAL 1 HOUR));
