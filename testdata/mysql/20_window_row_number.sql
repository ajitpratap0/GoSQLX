-- Window function ROW_NUMBER (MySQL 8.0+)
-- Complexity: Complex
-- Tests: ROW_NUMBER window function
SELECT
    name,
    department,
    salary,
    ROW_NUMBER() OVER (PARTITION BY department ORDER BY salary DESC) as dept_rank
FROM employees;
