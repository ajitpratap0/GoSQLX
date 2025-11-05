-- UNION ALL combining queries
-- Complexity: Medium
-- Tests: UNION ALL (includes duplicates)
SELECT id, name, 'active' as status FROM active_users
UNION ALL
SELECT id, name, 'inactive' as status FROM inactive_users
ORDER BY name;
