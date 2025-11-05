-- Oracle FIRST_VALUE and LAST_VALUE
-- Complexity: Complex
-- Tests: Window frame specification
SELECT
    department,
    name,
    salary,
    FIRST_VALUE(salary) OVER (PARTITION BY department ORDER BY salary DESC) as dept_max,
    LAST_VALUE(salary) OVER (PARTITION BY department ORDER BY salary RANGE BETWEEN CURRENT ROW AND UNBOUNDED FOLLOWING) as dept_min
FROM employees;
