-- Derived table (inline view)
-- Complexity: Medium
-- Tests: Derived table in FROM clause
SELECT
    dept_name,
    avg_salary
FROM (
    SELECT department_id, AVG(salary) as avg_salary
    FROM employees
    GROUP BY department_id
) dept_avg
JOIN departments d ON dept_avg.department_id = d.id;
