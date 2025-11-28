-- Sales funnel conversion analysis
-- Complexity: Complex
-- Tests: Multiple CTEs, aggregations, conversion rate calculations
WITH funnel_steps AS (
    SELECT
        'Page Views' as step,
        1 as step_order,
        COUNT(DISTINCT session_id) as users
    FROM page_views
    WHERE created_at >= CURRENT_DATE - INTERVAL '7 days'
    UNION ALL
    SELECT
        'Product Views' as step,
        2 as step_order,
        COUNT(DISTINCT session_id) as users
    FROM product_views
    WHERE created_at >= CURRENT_DATE - INTERVAL '7 days'
    UNION ALL
    SELECT
        'Add to Cart' as step,
        3 as step_order,
        COUNT(DISTINCT session_id) as users
    FROM cart_additions
    WHERE created_at >= CURRENT_DATE - INTERVAL '7 days'
    UNION ALL
    SELECT
        'Checkout Started' as step,
        4 as step_order,
        COUNT(DISTINCT session_id) as users
    FROM checkout_started
    WHERE created_at >= CURRENT_DATE - INTERVAL '7 days'
    UNION ALL
    SELECT
        'Order Completed' as step,
        5 as step_order,
        COUNT(DISTINCT session_id) as users
    FROM orders
    WHERE created_at >= CURRENT_DATE - INTERVAL '7 days' AND status = 'completed'
)
SELECT
    step,
    users,
    LAG(users) OVER (ORDER BY step_order) as prev_step_users,
    ROUND(100.0 * users / LAG(users) OVER (ORDER BY step_order), 2) as conversion_rate,
    ROUND(100.0 * users / FIRST_VALUE(users) OVER (ORDER BY step_order), 2) as overall_conversion
FROM funnel_steps
ORDER BY step_order;
