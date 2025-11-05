-- Product recommendation based on co-purchase patterns
-- Complexity: Complex
-- Tests: Self-joins, aggregations, ranking, filtering
WITH product_pairs AS (
    SELECT
        oi1.product_id as product_a,
        oi2.product_id as product_b,
        COUNT(DISTINCT oi1.order_id) as times_purchased_together
    FROM order_items oi1
    INNER JOIN order_items oi2 ON oi1.order_id = oi2.order_id AND oi1.product_id < oi2.product_id
    INNER JOIN orders o ON oi1.order_id = o.id
    WHERE o.status = 'completed'
        AND o.created_at >= CURRENT_DATE - INTERVAL '90 days'
    GROUP BY oi1.product_id, oi2.product_id
    HAVING COUNT(DISTINCT oi1.order_id) >= 5
),
ranked_recommendations AS (
    SELECT
        pp.product_a,
        pp.product_b,
        pp.times_purchased_together,
        ROW_NUMBER() OVER (PARTITION BY pp.product_a ORDER BY pp.times_purchased_together DESC) as rank
    FROM product_pairs pp
)
SELECT
    p1.name as product_name,
    p2.name as recommended_product,
    rr.times_purchased_together,
    rr.rank as recommendation_rank
FROM ranked_recommendations rr
INNER JOIN products p1 ON rr.product_a = p1.id
INNER JOIN products p2 ON rr.product_b = p2.id
WHERE rr.rank <= 5
ORDER BY p1.name, rr.rank;
