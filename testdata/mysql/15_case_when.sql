-- CASE WHEN expression
-- Complexity: Medium
-- Tests: CASE expression with multiple conditions
SELECT
    product_name,
    stock,
    CASE
        WHEN stock = 0 THEN 'Out of stock'
        WHEN stock < 10 THEN 'Low stock'
        WHEN stock < 50 THEN 'In stock'
        ELSE 'Well stocked'
    END as stock_status
FROM products;
