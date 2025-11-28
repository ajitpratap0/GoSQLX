-- Supply chain performance analytics
-- Complexity: Complex
-- Tests: Multiple JOINs, window functions, date calculations, performance metrics
WITH supplier_deliveries AS (
    SELECT
        po.supplier_id,
        po.id as po_id,
        po.order_date,
        po.expected_delivery_date,
        d.actual_delivery_date,
        EXTRACT(DAY FROM d.actual_delivery_date - po.expected_delivery_date) as delivery_delay_days,
        poi.quantity_ordered,
        poi.quantity_received,
        poi.unit_cost,
        CASE WHEN d.actual_delivery_date <= po.expected_delivery_date THEN 1 ELSE 0 END as on_time_delivery
    FROM purchase_orders po
    INNER JOIN purchase_order_items poi ON po.id = poi.purchase_order_id
    LEFT JOIN deliveries d ON po.id = d.purchase_order_id
    WHERE po.order_date >= CURRENT_DATE - INTERVAL '6 months'
),
supplier_metrics AS (
    SELECT
        supplier_id,
        COUNT(DISTINCT po_id) as total_orders,
        SUM(on_time_delivery) as on_time_deliveries,
        ROUND(100.0 * SUM(on_time_delivery) / COUNT(*), 2) as on_time_delivery_rate,
        AVG(delivery_delay_days) as avg_delay_days,
        SUM(quantity_ordered * unit_cost) as total_order_value,
        SUM((quantity_ordered - quantity_received) * unit_cost) as value_of_shortages
    FROM supplier_deliveries
    GROUP BY supplier_id
)
SELECT
    s.id,
    s.name,
    s.country,
    sm.total_orders,
    sm.on_time_delivery_rate,
    sm.avg_delay_days,
    sm.total_order_value,
    sm.value_of_shortages,
    RANK() OVER (ORDER BY sm.on_time_delivery_rate DESC) as reliability_rank,
    CASE
        WHEN sm.on_time_delivery_rate >= 95 AND sm.value_of_shortages < sm.total_order_value * 0.01 THEN 'A'
        WHEN sm.on_time_delivery_rate >= 90 AND sm.value_of_shortages < sm.total_order_value * 0.03 THEN 'B'
        WHEN sm.on_time_delivery_rate >= 80 THEN 'C'
        ELSE 'D'
    END as supplier_grade
FROM suppliers s
INNER JOIN supplier_metrics sm ON s.id = sm.supplier_id
ORDER BY sm.on_time_delivery_rate DESC, sm.total_order_value DESC;
