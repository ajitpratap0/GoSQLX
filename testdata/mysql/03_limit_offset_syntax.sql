-- MySQL LIMIT with offset syntax (LIMIT offset, count)
-- Complexity: Simple
-- Tests: MySQL-specific LIMIT offset syntax
SELECT id, title, created_at FROM posts ORDER BY created_at DESC LIMIT 10, 20;
