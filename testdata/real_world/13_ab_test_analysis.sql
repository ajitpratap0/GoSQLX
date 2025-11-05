-- A/B test statistical analysis
-- Complexity: Complex
-- Tests: Statistical calculations, aggregations, conversion analysis
WITH test_groups AS (
    SELECT
        variant,
        COUNT(DISTINCT user_id) as total_users,
        COUNT(DISTINCT CASE WHEN converted = true THEN user_id END) as converted_users,
        ROUND(100.0 * COUNT(DISTINCT CASE WHEN converted = true THEN user_id END) / COUNT(DISTINCT user_id), 2) as conversion_rate,
        AVG(time_to_conversion) as avg_time_to_conversion,
        SUM(revenue) as total_revenue,
        AVG(revenue) as avg_revenue_per_user
    FROM ab_test_results
    WHERE test_id = 'homepage_redesign_2024'
    GROUP BY variant
),
control_baseline AS (
    SELECT
        conversion_rate as control_conversion_rate,
        avg_revenue_per_user as control_arpu
    FROM test_groups
    WHERE variant = 'control'
)
SELECT
    tg.variant,
    tg.total_users,
    tg.converted_users,
    tg.conversion_rate,
    tg.conversion_rate - cb.control_conversion_rate as conversion_rate_lift,
    ROUND(((tg.conversion_rate - cb.control_conversion_rate) / cb.control_conversion_rate * 100), 2) as conversion_rate_improvement_pct,
    tg.avg_time_to_conversion,
    tg.total_revenue,
    tg.avg_revenue_per_user,
    tg.avg_revenue_per_user - cb.control_arpu as arpu_lift,
    ROUND(((tg.avg_revenue_per_user - cb.control_arpu) / cb.control_arpu * 100), 2) as arpu_improvement_pct,
    CASE
        WHEN tg.conversion_rate > cb.control_conversion_rate AND tg.total_users >= 1000 THEN 'Winner'
        WHEN tg.conversion_rate < cb.control_conversion_rate AND tg.total_users >= 1000 THEN 'Loser'
        WHEN tg.total_users < 1000 THEN 'Insufficient Data'
        ELSE 'Neutral'
    END as test_result
FROM test_groups tg
CROSS JOIN control_baseline cb
ORDER BY tg.conversion_rate DESC;
