-- Multiple CTEs in single query
-- Complexity: Complex
-- Tests: Multiple WITH clauses, CTE chaining
WITH sales_summary AS (
    SELECT user_id, SUM(total) as total_sales, COUNT(*) as order_count
    FROM orders
    WHERE status = 'completed'
    GROUP BY user_id
),
high_value_customers AS (
    SELECT user_id FROM sales_summary WHERE total_sales > 10000
)
SELECT u.name, ss.total_sales, ss.order_count
FROM users u
INNER JOIN sales_summary ss ON u.id = ss.user_id
WHERE u.id IN (SELECT user_id FROM high_value_customers);
