-- Recursive CTE (MySQL 8.0+)
-- Complexity: Complex
-- Tests: RECURSIVE CTE for hierarchical data
WITH RECURSIVE category_tree AS (
    SELECT id, name, parent_id, 1 as level
    FROM categories
    WHERE parent_id IS NULL
    UNION ALL
    SELECT c.id, c.name, c.parent_id, ct.level + 1
    FROM categories c
    INNER JOIN category_tree ct ON c.parent_id = ct.id
    WHERE ct.level < 5
)
SELECT * FROM category_tree ORDER BY level, name;
