-- SQL Server string functions
-- Complexity: Medium
-- Tests: STRING_SPLIT, CONCAT_WS, STRING_AGG
SELECT
    category,
    STRING_AGG(product_name, ', ') WITHIN GROUP (ORDER BY product_name) as products
FROM products
GROUP BY category;
