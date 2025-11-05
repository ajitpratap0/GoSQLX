-- IFNULL and COALESCE functions
-- Complexity: Simple
-- Tests: NULL handling functions
SELECT
    name,
    IFNULL(phone, 'N/A') as phone,
    COALESCE(mobile, phone, 'No contact') as contact
FROM users;
