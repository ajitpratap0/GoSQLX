-- FILTER clause in aggregate functions
-- Complexity: Medium
-- Tests: FILTER clause (PostgreSQL-specific)
SELECT
    department,
    COUNT(*) FILTER (WHERE salary > 50000) as high_earners,
    COUNT(*) FILTER (WHERE salary <= 50000) as low_earners
FROM employees
GROUP BY department;
