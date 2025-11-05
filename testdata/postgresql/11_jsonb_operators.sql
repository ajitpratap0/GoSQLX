-- PostgreSQL JSONB operators
-- Complexity: Medium
-- Tests: PostgreSQL-specific JSON operators (->>, @>, ?)
SELECT id, data->>'name' as name, data->>'email' as email
FROM user_profiles
WHERE data @> '{"active": true}' AND data ? 'premium';
