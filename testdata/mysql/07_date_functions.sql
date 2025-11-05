-- MySQL date functions
-- Complexity: Medium
-- Tests: DATE_FORMAT, DATE_ADD, DATE_SUB
SELECT
    order_date,
    DATE_FORMAT(order_date, '%Y-%m-%d') as formatted_date,
    DATE_ADD(order_date, INTERVAL 7 DAY) as delivery_date
FROM orders
WHERE order_date > DATE_SUB(NOW(), INTERVAL 30 DAY);
