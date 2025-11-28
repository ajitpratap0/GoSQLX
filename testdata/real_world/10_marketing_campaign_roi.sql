-- Marketing campaign ROI analysis
-- Complexity: Complex
-- Tests: Multiple CTEs, aggregations, ROI calculations, ranking
WITH campaign_costs AS (
    SELECT
        campaign_id,
        SUM(cost) as total_cost
    FROM marketing_expenses
    GROUP BY campaign_id
),
campaign_conversions AS (
    SELECT
        c.campaign_id,
        COUNT(DISTINCT c.user_id) as total_conversions,
        COUNT(DISTINCT o.id) as total_orders,
        SUM(o.total) as total_revenue
    FROM campaign_clicks c
    LEFT JOIN orders o ON c.user_id = o.user_id
        AND o.created_at BETWEEN c.clicked_at AND c.clicked_at + INTERVAL '30 days'
    GROUP BY c.campaign_id
),
campaign_metrics AS (
    SELECT
        mc.id as campaign_id,
        mc.name as campaign_name,
        mc.channel,
        cc.total_cost,
        COALESCE(cv.total_conversions, 0) as conversions,
        COALESCE(cv.total_orders, 0) as orders,
        COALESCE(cv.total_revenue, 0) as revenue,
        COALESCE(cv.total_revenue, 0) - cc.total_cost as profit,
        CASE
            WHEN cc.total_cost > 0 THEN
                ROUND(((COALESCE(cv.total_revenue, 0) - cc.total_cost) / cc.total_cost * 100), 2)
            ELSE 0
        END as roi_percentage,
        CASE
            WHEN COALESCE(cv.total_conversions, 0) > 0 THEN
                ROUND(cc.total_cost / cv.total_conversions, 2)
            ELSE 0
        END as cost_per_conversion
    FROM marketing_campaigns mc
    INNER JOIN campaign_costs cc ON mc.id = cc.campaign_id
    LEFT JOIN campaign_conversions cv ON mc.id = cv.campaign_id
)
SELECT
    *,
    RANK() OVER (ORDER BY roi_percentage DESC) as roi_rank,
    RANK() OVER (ORDER BY cost_per_conversion) as efficiency_rank
FROM campaign_metrics
WHERE total_cost > 0
ORDER BY roi_percentage DESC;
