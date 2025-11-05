-- Recursive CTE for hierarchical data
-- Complexity: Complex
-- Tests: RECURSIVE CTE, UNION ALL, hierarchical queries
WITH RECURSIVE employee_hierarchy AS (
    SELECT id, name, manager_id, 1 as level
    FROM employees
    WHERE manager_id IS NULL
    UNION ALL
    SELECT e.id, e.name, e.manager_id, eh.level + 1
    FROM employees e
    INNER JOIN employee_hierarchy eh ON e.manager_id = eh.id
    WHERE eh.level < 10
)
SELECT * FROM employee_hierarchy ORDER BY level, name;
