-- Multi-currency revenue reporting with exchange rates
-- Complexity: Complex
-- Tests: Currency conversion, date-based joins, aggregations, exchange rate handling
WITH daily_exchange_rates AS (
    SELECT
        currency_code,
        rate_date,
        rate_to_usd,
        ROW_NUMBER() OVER (PARTITION BY currency_code, rate_date ORDER BY updated_at DESC) as rn
    FROM exchange_rates
    WHERE rate_date >= CURRENT_DATE - INTERVAL '90 days'
),
latest_rates AS (
    SELECT currency_code, rate_date, rate_to_usd
    FROM daily_exchange_rates
    WHERE rn = 1
),
orders_with_conversion AS (
    SELECT
        o.id,
        o.customer_id,
        o.order_date,
        o.total as original_amount,
        o.currency,
        COALESCE(er.rate_to_usd, 1.0) as exchange_rate,
        o.total * COALESCE(er.rate_to_usd, 1.0) as amount_usd,
        c.country,
        c.region
    FROM orders o
    LEFT JOIN latest_rates er ON o.currency = er.currency_code AND DATE(o.order_date) = er.rate_date
    INNER JOIN customers c ON o.customer_id = c.id
    WHERE o.status = 'completed'
        AND o.order_date >= CURRENT_DATE - INTERVAL '90 days'
),
revenue_summary AS (
    SELECT
        DATE_TRUNC('month', order_date) as revenue_month,
        country,
        region,
        currency,
        COUNT(DISTINCT id) as order_count,
        COUNT(DISTINCT customer_id) as unique_customers,
        SUM(original_amount) as total_local_currency,
        SUM(amount_usd) as total_usd,
        AVG(amount_usd) as avg_order_value_usd
    FROM orders_with_conversion
    GROUP BY DATE_TRUNC('month', order_date), country, region, currency
)
SELECT
    revenue_month,
    country,
    region,
    currency,
    order_count,
    unique_customers,
    ROUND(total_local_currency, 2) as revenue_local,
    ROUND(total_usd, 2) as revenue_usd,
    ROUND(avg_order_value_usd, 2) as avg_order_usd,
    ROUND(100.0 * total_usd / SUM(total_usd) OVER (PARTITION BY revenue_month), 2) as pct_of_monthly_revenue,
    RANK() OVER (PARTITION BY revenue_month ORDER BY total_usd DESC) as revenue_rank
FROM revenue_summary
ORDER BY revenue_month DESC, total_usd DESC;
