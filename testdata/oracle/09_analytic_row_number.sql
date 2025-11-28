-- Oracle analytic functions (ROW_NUMBER)
-- Complexity: Complex
-- Tests: ROW_NUMBER with PARTITION BY
SELECT
    name,
    department,
    salary,
    ROW_NUMBER() OVER (PARTITION BY department ORDER BY salary DESC) as dept_rank
FROM employees;
