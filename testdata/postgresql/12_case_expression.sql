-- CASE expression with multiple conditions
-- Complexity: Medium
-- Tests: CASE WHEN, complex conditions
SELECT
    name,
    salary,
    CASE
        WHEN salary > 100000 THEN 'High'
        WHEN salary > 50000 THEN 'Medium'
        ELSE 'Low'
    END as salary_category
FROM employees
ORDER BY salary DESC;
