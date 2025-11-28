-- PostgreSQL array operators
-- Complexity: Medium
-- Tests: PostgreSQL-specific array operators (@>, ANY, ALL)
SELECT * FROM users WHERE tags @> ARRAY['admin', 'moderator'];
