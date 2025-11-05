-- Window functions LAG and LEAD (MySQL 8.0+)
-- Complexity: Complex
-- Tests: LAG, LEAD with default values
SELECT
    date,
    sales,
    LAG(sales, 1, 0) OVER (ORDER BY date) as prev_day_sales,
    LEAD(sales, 1, 0) OVER (ORDER BY date) as next_day_sales
FROM daily_sales
ORDER BY date;
