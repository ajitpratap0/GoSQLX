-- DATEPART and DATEADD functions
-- Complexity: Medium
-- Tests: SQL Server date manipulation
SELECT
    order_date,
    DATEPART(YEAR, order_date) as order_year,
    DATEPART(MONTH, order_date) as order_month,
    DATEADD(DAY, 7, order_date) as expected_delivery
FROM orders
WHERE order_date > DATEADD(MONTH, -3, GETDATE());
