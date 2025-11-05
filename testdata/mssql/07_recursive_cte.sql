-- Recursive CTE for organizational hierarchy
-- Complexity: Complex
-- Tests: RECURSIVE CTE with MAXRECURSION option
WITH EmployeeHierarchy AS (
    SELECT id, name, manager_id, 1 as level
    FROM employees
    WHERE manager_id IS NULL
    UNION ALL
    SELECT e.id, e.name, e.manager_id, eh.level + 1
    FROM employees e
    INNER JOIN EmployeeHierarchy eh ON e.manager_id = eh.id
)
SELECT * FROM EmployeeHierarchy
ORDER BY level, name
OPTION (MAXRECURSION 100);
