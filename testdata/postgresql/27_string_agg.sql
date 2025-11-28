-- PostgreSQL STRING_AGG function
-- Complexity: Medium
-- Tests: STRING_AGG aggregate function
SELECT
    category_id,
    STRING_AGG(product_name, ', ' ORDER BY product_name) as products
FROM products
GROUP BY category_id;
