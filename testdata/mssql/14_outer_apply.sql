-- OUTER APPLY operator (SQL Server-specific)
-- Complexity: Complex
-- Tests: OUTER APPLY (like LEFT JOIN for table-valued functions)
SELECT u.name, recent_orders.order_count
FROM users u
OUTER APPLY (
    SELECT COUNT(*) as order_count
    FROM orders
    WHERE user_id = u.id
    AND order_date > DATEADD(MONTH, -6, GETDATE())
) AS recent_orders;
