-- Oracle LISTAGG function
-- Complexity: Medium
-- Tests: LISTAGG for string aggregation
SELECT
    category_id,
    LISTAGG(product_name, ', ') WITHIN GROUP (ORDER BY product_name) as products
FROM products
GROUP BY category_id;
