SELECT id, name, parent_id FROM categories START WITH parent_id IS NULL CONNECT BY PRIOR id = parent_id;
SELECT id, name FROM employees CONNECT BY NOCYCLE PRIOR manager_id = id;
SELECT id, name, parent_id
FROM employees
CONNECT BY id = PRIOR parent_id;
SELECT id, name, parent_id
FROM employees
START WITH id = 1
CONNECT BY NOCYCLE id = PRIOR parent_id;
