-- Multiple JOIN operations
-- Complexity: Medium
-- Tests: Multiple JOINs, mixed JOIN types
SELECT
    c.name as customer_name,
    o.order_date,
    p.product_name,
    oi.quantity,
    oi.price
FROM customers c
INNER JOIN orders o ON c.id = o.customer_id
INNER JOIN order_items oi ON o.id = oi.order_id
INNER JOIN products p ON oi.product_id = p.id
WHERE o.status = 'shipped'
ORDER BY o.order_date DESC;
