-- Oracle SYS_CONNECT_BY_PATH
-- Complexity: Complex
-- Tests: Path generation in hierarchical queries
SELECT
    name,
    SYS_CONNECT_BY_PATH(name, '/') as path,
    LEVEL
FROM categories
START WITH parent_id IS NULL
CONNECT BY PRIOR id = parent_id;
