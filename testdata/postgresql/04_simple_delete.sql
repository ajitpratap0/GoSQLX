-- Simple DELETE statement
-- Complexity: Simple
-- Tests: DELETE with WHERE clause
DELETE FROM sessions WHERE expires_at < NOW();
