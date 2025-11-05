-- Window functions LAG and LEAD
-- Complexity: Complex
-- Tests: LAG, LEAD with default values
SELECT
    date,
    sales,
    LAG(sales, 1, 0) OVER (ORDER BY date) as prev_day_sales,
    LEAD(sales, 1, 0) OVER (ORDER BY date) as next_day_sales,
    sales - LAG(sales, 1, 0) OVER (ORDER BY date) as daily_change
FROM daily_sales;
