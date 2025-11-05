-- MySQL JSON functions
-- Complexity: Medium
-- Tests: JSON_EXTRACT, JSON path expressions
SELECT
    id,
    JSON_EXTRACT(data, '$.name') as name,
    JSON_EXTRACT(data, '$.email') as email
FROM user_profiles
WHERE JSON_EXTRACT(data, '$.active') = true;
