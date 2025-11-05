-- Inventory reorder report with sales velocity
-- Complexity: Complex
-- Tests: Window functions, aggregations, derived tables, business logic
WITH daily_sales AS (
    SELECT
        product_id,
        DATE(order_date) as sale_date,
        SUM(quantity) as units_sold
    FROM order_items oi
    INNER JOIN orders o ON oi.order_id = o.id
    WHERE o.status = 'completed'
        AND o.order_date >= CURRENT_DATE - INTERVAL '30 days'
    GROUP BY product_id, DATE(order_date)
),
sales_velocity AS (
    SELECT
        product_id,
        AVG(units_sold) as avg_daily_sales,
        MAX(units_sold) as peak_daily_sales,
        STDDEV(units_sold) as sales_volatility
    FROM daily_sales
    GROUP BY product_id
)
SELECT
    p.id,
    p.name,
    p.sku,
    p.current_stock,
    sv.avg_daily_sales,
    sv.peak_daily_sales,
    ROUND(p.current_stock / NULLIF(sv.avg_daily_sales, 0), 1) as days_of_inventory,
    CASE
        WHEN p.current_stock < sv.avg_daily_sales * 7 THEN 'URGENT'
        WHEN p.current_stock < sv.avg_daily_sales * 14 THEN 'REORDER'
        ELSE 'OK'
    END as reorder_status
FROM products p
LEFT JOIN sales_velocity sv ON p.id = sv.product_id
WHERE p.active = true
ORDER BY
    CASE
        WHEN p.current_stock < sv.avg_daily_sales * 7 THEN 1
        WHEN p.current_stock < sv.avg_daily_sales * 14 THEN 2
        ELSE 3
    END,
    days_of_inventory;
