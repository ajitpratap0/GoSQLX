-- LATERAL JOIN (PostgreSQL feature)
-- Complexity: Complex
-- Tests: LATERAL keyword, correlated subquery in FROM
SELECT u.name, recent_orders.order_date, recent_orders.total
FROM users u
CROSS JOIN LATERAL (
    SELECT order_date, total
    FROM orders
    WHERE user_id = u.id
    ORDER BY order_date DESC
    LIMIT 5
) recent_orders;
