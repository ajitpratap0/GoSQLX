SELECT id, name, parent_id FROM categories START WITH parent_id IS NULL CONNECT BY PRIOR id = parent_id;
SELECT id, name FROM employees CONNECT BY NOCYCLE PRIOR manager_id = id;
