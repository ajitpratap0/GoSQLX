-- Oracle LAG and LEAD functions
-- Complexity: Complex
-- Tests: LAG, LEAD with offset and default
SELECT
    date_col,
    sales,
    LAG(sales, 1, 0) OVER (ORDER BY date_col) as prev_day,
    LEAD(sales, 1, 0) OVER (ORDER BY date_col) as next_day
FROM daily_sales;
