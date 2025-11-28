-- Oracle NVL and NVL2 functions
-- Complexity: Simple
-- Tests: NULL handling functions
SELECT
    name,
    NVL(phone, 'N/A') as phone,
    NVL2(email, 'Has Email', 'No Email') as email_status
FROM users;
