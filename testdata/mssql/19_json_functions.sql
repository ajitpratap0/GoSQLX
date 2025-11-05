-- SQL Server JSON functions (SQL Server 2016+)
-- Complexity: Medium
-- Tests: JSON_VALUE, JSON_QUERY, OPENJSON
SELECT
    id,
    JSON_VALUE(data, '$.name') as name,
    JSON_VALUE(data, '$.email') as email
FROM user_profiles
WHERE JSON_VALUE(data, '$.active') = 'true';
