-- INSERT SELECT statement
-- Complexity: Medium
-- Tests: INSERT with SELECT subquery
INSERT INTO archive_orders (order_id, user_id, total, archived_at)
SELECT id, user_id, total, NOW()
FROM orders
WHERE status = 'completed' AND created_at < DATE_SUB(NOW(), INTERVAL 1 YEAR);
