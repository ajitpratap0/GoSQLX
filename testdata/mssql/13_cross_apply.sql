-- CROSS APPLY operator (SQL Server-specific)
-- Complexity: Complex
-- Tests: CROSS APPLY with table-valued function
SELECT u.name, top_orders.order_date, top_orders.total
FROM users u
CROSS APPLY (
    SELECT TOP 3 order_date, total
    FROM orders
    WHERE user_id = u.id
    ORDER BY order_date DESC
) AS top_orders;
