-- NTILE window function
-- Complexity: Complex
-- Tests: NTILE for percentile distribution
SELECT
    name,
    salary,
    NTILE(4) OVER (ORDER BY salary) as quartile
FROM employees;
