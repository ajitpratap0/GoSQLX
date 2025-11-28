-- Window aggregate functions with frame specification
-- Complexity: Complex
-- Tests: SUM, AVG with ROWS BETWEEN frame specification
SELECT
    date,
    amount,
    SUM(amount) OVER (ORDER BY date ROWS BETWEEN 2 PRECEDING AND CURRENT ROW) as rolling_sum_3day,
    AVG(amount) OVER (ORDER BY date ROWS BETWEEN 6 PRECEDING AND CURRENT ROW) as rolling_avg_7day
FROM transactions
ORDER BY date;
