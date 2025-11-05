-- Customer Lifetime Value (CLV) calculation
-- Complexity: Complex
-- Tests: CTEs, aggregations, window functions, complex business logic
WITH customer_orders AS (
    SELECT
        customer_id,
        COUNT(*) as order_count,
        SUM(total) as total_spent,
        MIN(created_at) as first_order,
        MAX(created_at) as last_order,
        AVG(total) as avg_order_value
    FROM orders
    WHERE status = 'completed'
    GROUP BY customer_id
),
customer_segments AS (
    SELECT
        co.*,
        CASE
            WHEN co.order_count >= 10 AND co.total_spent > 5000 THEN 'VIP'
            WHEN co.order_count >= 5 AND co.total_spent > 2000 THEN 'Loyal'
            WHEN co.order_count >= 2 THEN 'Regular'
            ELSE 'New'
        END as segment
    FROM customer_orders co
)
SELECT
    c.id,
    c.name,
    c.email,
    cs.order_count,
    cs.total_spent,
    cs.avg_order_value,
    cs.segment,
    DATEDIFF(cs.last_order, cs.first_order) as customer_age_days
FROM customers c
INNER JOIN customer_segments cs ON c.id = cs.customer_id
WHERE cs.segment IN ('VIP', 'Loyal')
ORDER BY cs.total_spent DESC;
