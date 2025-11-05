-- MySQL GROUP_CONCAT function
-- Complexity: Medium
-- Tests: GROUP_CONCAT aggregate
SELECT
    category_id,
    GROUP_CONCAT(product_name ORDER BY product_name SEPARATOR ', ') as products
FROM products
GROUP BY category_id;
