-- Oracle WITH clause (subquery factoring)
-- Complexity: Complex
-- Tests: CTE in Oracle
WITH sales_summary AS (
    SELECT
        customer_id,
        SUM(total) as total_sales,
        COUNT(*) as order_count
    FROM orders
    WHERE status = 'completed'
    GROUP BY customer_id
)
SELECT c.name, s.total_sales, s.order_count
FROM customers c
JOIN sales_summary s ON c.id = s.customer_id
WHERE s.total_sales > 10000
ORDER BY s.total_sales DESC;
