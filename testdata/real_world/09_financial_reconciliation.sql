-- Financial reconciliation report with discrepancy detection
-- Complexity: Complex
-- Tests: FULL OUTER JOIN, aggregations, NULL handling, variance analysis
WITH order_totals AS (
    SELECT
        order_id,
        SUM(quantity * price) as calculated_total
    FROM order_items
    GROUP BY order_id
),
payment_totals AS (
    SELECT
        order_id,
        SUM(amount) as payment_total
    FROM payments
    WHERE status = 'completed'
    GROUP BY order_id
)
SELECT
    COALESCE(o.id, pt.order_id) as order_id,
    o.total as order_table_total,
    ot.calculated_total,
    pt.payment_total,
    CASE
        WHEN o.total IS NULL THEN 'Missing Order'
        WHEN ot.calculated_total IS NULL THEN 'Missing Items'
        WHEN pt.payment_total IS NULL THEN 'Missing Payment'
        WHEN ABS(o.total - ot.calculated_total) > 0.01 THEN 'Order/Items Mismatch'
        WHEN ABS(o.total - COALESCE(pt.payment_total, 0)) > 0.01 THEN 'Order/Payment Mismatch'
        ELSE 'OK'
    END as reconciliation_status,
    ABS(COALESCE(o.total, 0) - COALESCE(ot.calculated_total, 0)) as order_items_variance,
    ABS(COALESCE(o.total, 0) - COALESCE(pt.payment_total, 0)) as order_payment_variance
FROM orders o
FULL OUTER JOIN order_totals ot ON o.id = ot.order_id
FULL OUTER JOIN payment_totals pt ON COALESCE(o.id, ot.order_id) = pt.order_id
WHERE
    o.total IS NULL
    OR ot.calculated_total IS NULL
    OR pt.payment_total IS NULL
    OR ABS(o.total - ot.calculated_total) > 0.01
    OR ABS(o.total - COALESCE(pt.payment_total, 0)) > 0.01
ORDER BY order_payment_variance DESC;
