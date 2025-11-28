-- Common Table Expression (MySQL 8.0+)
-- Complexity: Complex
-- Tests: WITH clause, CTE
WITH sales_data AS (
    SELECT
        product_id,
        SUM(quantity) as total_quantity,
        SUM(price * quantity) as total_revenue
    FROM order_items
    GROUP BY product_id
)
SELECT
    p.product_name,
    sd.total_quantity,
    sd.total_revenue
FROM products p
JOIN sales_data sd ON p.id = sd.product_id
WHERE sd.total_revenue > 10000
ORDER BY sd.total_revenue DESC;
