-- E-commerce dashboard query with revenue analytics
-- Complexity: Complex
-- Tests: Multiple JOINs, aggregations, date functions, window functions
SELECT
    DATE(o.created_at) as order_date,
    COUNT(DISTINCT o.id) as total_orders,
    COUNT(DISTINCT o.customer_id) as unique_customers,
    SUM(oi.quantity * oi.price) as daily_revenue,
    AVG(oi.quantity * oi.price) as avg_order_value,
    SUM(SUM(oi.quantity * oi.price)) OVER (ORDER BY DATE(o.created_at) ROWS BETWEEN 6 PRECEDING AND CURRENT ROW) as rolling_7day_revenue
FROM orders o
INNER JOIN order_items oi ON o.id = oi.order_id
WHERE o.status = 'completed'
    AND o.created_at >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY DATE(o.created_at)
ORDER BY order_date DESC;
