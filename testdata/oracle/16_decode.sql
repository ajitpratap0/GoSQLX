-- Oracle DECODE function
-- Complexity: Medium
-- Tests: DECODE for conditional logic
SELECT
    name,
    status,
    DECODE(status, 1, 'Active', 2, 'Inactive', 3, 'Pending', 'Unknown') as status_text
FROM users;
