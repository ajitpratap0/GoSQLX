-- MySQL IF function
-- Complexity: Medium
-- Tests: IF function in SELECT
SELECT
    name,
    salary,
    IF(salary > 50000, 'High', 'Low') as salary_category
FROM employees;
