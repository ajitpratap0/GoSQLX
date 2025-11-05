-- REGEXP pattern matching
-- Complexity: Medium
-- Tests: REGEXP operator
SELECT name, email
FROM users
WHERE email REGEXP '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$';
