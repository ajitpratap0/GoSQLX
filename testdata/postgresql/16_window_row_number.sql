-- Window function with ROW_NUMBER
-- Complexity: Complex
-- Tests: Window functions, ROW_NUMBER, PARTITION BY, ORDER BY
SELECT
    name,
    department,
    salary,
    ROW_NUMBER() OVER (PARTITION BY department ORDER BY salary DESC) as rank
FROM employees;
