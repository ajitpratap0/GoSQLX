-- INTERSECT set operation
-- Complexity: Medium
-- Tests: INTERSECT operator
SELECT product_id FROM inventory
INTERSECT
SELECT product_id FROM active_products;
