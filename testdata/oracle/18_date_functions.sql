-- Oracle date functions
-- Complexity: Medium
-- Tests: TO_DATE, ADD_MONTHS, MONTHS_BETWEEN
SELECT
    order_date,
    TO_CHAR(order_date, 'YYYY-MM-DD') as formatted_date,
    ADD_MONTHS(order_date, 1) as next_month,
    MONTHS_BETWEEN(SYSDATE, order_date) as months_ago
FROM orders
WHERE order_date > ADD_MONTHS(SYSDATE, -3);
