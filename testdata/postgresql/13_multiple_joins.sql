-- Multiple JOINs with different types
-- Complexity: Medium
-- Tests: Multiple JOINs, LEFT JOIN, INNER JOIN combination
SELECT
    u.name,
    o.order_date,
    p.product_name,
    c.category_name
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
INNER JOIN order_items oi ON o.id = oi.order_id
INNER JOIN products p ON oi.product_id = p.id
LEFT JOIN categories c ON p.category_id = c.id
WHERE u.active = true;
