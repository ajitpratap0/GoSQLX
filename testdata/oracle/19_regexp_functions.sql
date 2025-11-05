-- Oracle regular expression functions
-- Complexity: Medium
-- Tests: REGEXP_LIKE, REGEXP_SUBSTR
SELECT name, email
FROM users
WHERE REGEXP_LIKE(email, '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$');
