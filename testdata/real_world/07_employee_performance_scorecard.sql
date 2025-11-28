-- Employee performance scorecard with KPIs
-- Complexity: Complex
-- Tests: Window functions, aggregations, complex calculations, ranking
WITH monthly_metrics AS (
    SELECT
        employee_id,
        DATE_TRUNC('month', sale_date) as month,
        COUNT(*) as deals_closed,
        SUM(amount) as revenue_generated,
        AVG(amount) as avg_deal_size,
        COUNT(DISTINCT customer_id) as customers_served
    FROM sales
    WHERE sale_date >= CURRENT_DATE - INTERVAL '12 months'
    GROUP BY employee_id, DATE_TRUNC('month', sale_date)
),
employee_rankings AS (
    SELECT
        mm.*,
        RANK() OVER (PARTITION BY mm.month ORDER BY mm.revenue_generated DESC) as revenue_rank,
        RANK() OVER (PARTITION BY mm.month ORDER BY mm.deals_closed DESC) as deals_rank,
        AVG(mm.revenue_generated) OVER (PARTITION BY mm.employee_id) as avg_monthly_revenue
    FROM monthly_metrics mm
)
SELECT
    e.id,
    e.name,
    e.department,
    er.month,
    er.deals_closed,
    er.revenue_generated,
    er.avg_deal_size,
    er.revenue_rank,
    er.deals_rank,
    CASE
        WHEN er.revenue_rank <= 3 AND er.deals_rank <= 3 THEN 'Excellent'
        WHEN er.revenue_rank <= 10 THEN 'Good'
        WHEN er.revenue_generated >= er.avg_monthly_revenue THEN 'Average'
        ELSE 'Needs Improvement'
    END as performance_rating
FROM employees e
INNER JOIN employee_rankings er ON e.id = er.employee_id
WHERE er.month >= CURRENT_DATE - INTERVAL '3 months'
ORDER BY er.month DESC, er.revenue_rank;
