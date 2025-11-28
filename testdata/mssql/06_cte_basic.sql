-- Common Table Expression
-- Complexity: Complex
-- Tests: WITH clause for CTE
WITH SalesCTE AS (
    SELECT
        customer_id,
        SUM(total) as total_sales
    FROM orders
    WHERE status = 'completed'
    GROUP BY customer_id
)
SELECT c.name, s.total_sales
FROM customers c
INNER JOIN SalesCTE s ON c.id = s.customer_id
WHERE s.total_sales > 5000;
