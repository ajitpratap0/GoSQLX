-- Time series data preparation for forecasting
-- Complexity: Complex
-- Tests: Window functions, date series, trend analysis, seasonality
WITH date_series AS (
    SELECT generate_series(
        DATE_TRUNC('day', CURRENT_DATE - INTERVAL '365 days'),
        DATE_TRUNC('day', CURRENT_DATE),
        INTERVAL '1 day'
    )::date as date
),
daily_sales AS (
    SELECT
        DATE(order_date) as date,
        SUM(total) as revenue,
        COUNT(*) as order_count,
        COUNT(DISTINCT customer_id) as unique_customers
    FROM orders
    WHERE status = 'completed'
    GROUP BY DATE(order_date)
),
sales_with_trends AS (
    SELECT
        ds.date,
        COALESCE(d.revenue, 0) as revenue,
        COALESCE(d.order_count, 0) as order_count,
        COALESCE(d.unique_customers, 0) as unique_customers,
        EXTRACT(DOW FROM ds.date) as day_of_week,
        EXTRACT(MONTH FROM ds.date) as month,
        AVG(COALESCE(d.revenue, 0)) OVER (ORDER BY ds.date ROWS BETWEEN 6 PRECEDING AND CURRENT ROW) as ma_7day,
        AVG(COALESCE(d.revenue, 0)) OVER (ORDER BY ds.date ROWS BETWEEN 29 PRECEDING AND CURRENT ROW) as ma_30day,
        LAG(COALESCE(d.revenue, 0), 7) OVER (ORDER BY ds.date) as revenue_same_day_last_week,
        LAG(COALESCE(d.revenue, 0), 365) OVER (ORDER BY ds.date) as revenue_same_day_last_year
    FROM date_series ds
    LEFT JOIN daily_sales d ON ds.date = d.date
)
SELECT
    date,
    revenue,
    order_count,
    unique_customers,
    day_of_week,
    month,
    ma_7day,
    ma_30day,
    revenue_same_day_last_week,
    revenue - revenue_same_day_last_week as wow_change,
    CASE
        WHEN revenue_same_day_last_week > 0 THEN
            ROUND(((revenue - revenue_same_day_last_week) / revenue_same_day_last_week * 100), 2)
        ELSE NULL
    END as wow_change_pct,
    revenue_same_day_last_year,
    revenue - revenue_same_day_last_year as yoy_change,
    CASE
        WHEN revenue_same_day_last_year > 0 THEN
            ROUND(((revenue - revenue_same_day_last_year) / revenue_same_day_last_year * 100), 2)
        ELSE NULL
    END as yoy_change_pct
FROM sales_with_trends
WHERE date >= CURRENT_DATE - INTERVAL '90 days'
ORDER BY date;
