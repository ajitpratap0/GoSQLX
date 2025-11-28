-- Window functions with LAG and LEAD
-- Complexity: Complex
-- Tests: LAG, LEAD window functions with offset and default
SELECT
    date,
    revenue,
    LAG(revenue, 1, 0) OVER (ORDER BY date) as prev_revenue,
    LEAD(revenue, 1, 0) OVER (ORDER BY date) as next_revenue
FROM daily_sales
ORDER BY date;
