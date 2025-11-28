-- Oracle CONNECT BY for hierarchical queries
-- Complexity: Complex
-- Tests: CONNECT BY PRIOR for tree structures
SELECT
    LEVEL,
    id,
    name,
    manager_id
FROM employees
START WITH manager_id IS NULL
CONNECT BY PRIOR id = manager_id
ORDER SIBLINGS BY name;
