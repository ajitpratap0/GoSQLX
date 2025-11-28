-- Real-World E-Commerce Platform SQL Queries
-- Based on actual production database patterns

-- Query 1: Customer Lifetime Value (CLV) calculation
SELECT
    u.id,
    u.email,
    COUNT(o.id) as total_orders,
    SUM(o.total) as lifetime_value,
    AVG(o.total) as avg_order_value,
    MIN(o.created_at) as first_order,
    MAX(o.created_at) as last_order
FROM users u
INNER JOIN orders o ON u.id = o.user_id
WHERE o.status = 'completed'
GROUP BY u.id, u.email
HAVING lifetime_value > 1000
ORDER BY lifetime_value DESC
LIMIT 100;

-- Query 2: Top selling products by category
SELECT
    c.name as category,
    p.name as product,
    COUNT(oi.id) as times_ordered,
    SUM(oi.quantity) as total_quantity,
    SUM(oi.quantity * oi.price) as total_revenue
FROM categories c
INNER JOIN products p ON c.id = p.category_id
INNER JOIN order_items oi ON p.id = oi.product_id
INNER JOIN orders o ON oi.order_id = o.id
WHERE o.created_at >= '2024-01-01'
    AND o.status = 'completed'
GROUP BY c.id, c.name, p.id, p.name
ORDER BY c.name, total_revenue DESC;

-- Query 3: Cart abandonment analysis
SELECT
    DATE(c.created_at) as cart_date,
    COUNT(DISTINCT c.id) as total_carts,
    COUNT(DISTINCT o.id) as converted_carts,
    COUNT(DISTINCT o.id) * 100.0 / COUNT(DISTINCT c.id) as conversion_rate,
    SUM(c.total) as potential_revenue,
    SUM(o.total) as actual_revenue
FROM carts c
LEFT JOIN orders o ON c.user_id = o.user_id
    AND DATE(c.created_at) = DATE(o.created_at)
WHERE c.created_at >= '2024-01-01'
GROUP BY DATE(c.created_at)
ORDER BY cart_date DESC;

-- Query 4: Inventory restock recommendations
SELECT
    p.id,
    p.name,
    p.stock_quantity as current_stock,
    AVG(daily_sales.daily_qty) as avg_daily_sales,
    p.stock_quantity / NULLIF(AVG(daily_sales.daily_qty), 0) as days_remaining
FROM products p
INNER JOIN (
    SELECT
        product_id,
        DATE(o.created_at) as sale_date,
        SUM(oi.quantity) as daily_qty
    FROM order_items oi
    INNER JOIN orders o ON oi.order_id = o.id
    WHERE o.created_at >= '2024-01-01'
        AND o.status = 'completed'
    GROUP BY product_id, DATE(o.created_at)
) daily_sales ON p.id = daily_sales.product_id
WHERE p.active = true
GROUP BY p.id, p.name, p.stock_quantity
HAVING days_remaining < 14
ORDER BY days_remaining ASC;

-- Query 5: Customer segmentation (RFM analysis)
SELECT
    user_id,
    DATEDIFF(NOW(), MAX(order_date)) as recency_days,
    COUNT(*) as frequency,
    SUM(total) as monetary_value,
    CASE
        WHEN DATEDIFF(NOW(), MAX(order_date)) <= 30 THEN 'Active'
        WHEN DATEDIFF(NOW(), MAX(order_date)) <= 90 THEN 'At Risk'
        WHEN DATEDIFF(NOW(), MAX(order_date)) <= 180 THEN 'Dormant'
        ELSE 'Lost'
    END as customer_status
FROM orders
WHERE status = 'completed'
GROUP BY user_id
ORDER BY monetary_value DESC;

-- Query 6: Product recommendation - frequently bought together
SELECT
    p1.id as product_id,
    p1.name as product_name,
    p2.id as recommended_product_id,
    p2.name as recommended_product_name,
    COUNT(*) as times_bought_together
FROM order_items oi1
INNER JOIN order_items oi2 ON oi1.order_id = oi2.order_id
    AND oi1.product_id < oi2.product_id
INNER JOIN products p1 ON oi1.product_id = p1.id
INNER JOIN products p2 ON oi2.product_id = p2.id
GROUP BY p1.id, p1.name, p2.id, p2.name
HAVING times_bought_together > 5
ORDER BY p1.id, times_bought_together DESC;

-- Query 7: Revenue by traffic source
SELECT
    traffic_source,
    COUNT(DISTINCT user_id) as unique_visitors,
    COUNT(DISTINCT order_id) as conversions,
    COUNT(DISTINCT order_id) * 100.0 / COUNT(DISTINCT user_id) as conversion_rate,
    SUM(order_total) as total_revenue,
    AVG(order_total) as avg_order_value
FROM (
    SELECT
        u.traffic_source,
        s.user_id,
        o.id as order_id,
        o.total as order_total
    FROM sessions s
    INNER JOIN users u ON s.user_id = u.id
    LEFT JOIN orders o ON s.id = o.session_id
    WHERE s.created_at >= '2024-01-01'
) source_data
GROUP BY traffic_source
ORDER BY total_revenue DESC;

-- Query 8: Seasonal trends analysis
SELECT
    EXTRACT(YEAR FROM order_date) as year,
    EXTRACT(QUARTER FROM order_date) as quarter,
    c.name as category,
    COUNT(*) as order_count,
    SUM(oi.quantity) as units_sold,
    SUM(oi.quantity * oi.price) as revenue
FROM orders o
INNER JOIN order_items oi ON o.id = oi.order_id
INNER JOIN products p ON oi.product_id = p.id
INNER JOIN categories c ON p.category_id = c.id
WHERE o.status = 'completed'
GROUP BY EXTRACT(YEAR FROM order_date),
         EXTRACT(QUARTER FROM order_date),
         c.id, c.name
ORDER BY year DESC, quarter DESC, revenue DESC;

-- Query 9: Customer retention cohort analysis
SELECT
    DATE_TRUNC('month', first_order) as cohort_month,
    COUNT(DISTINCT user_id) as cohort_size,
    COUNT(DISTINCT CASE WHEN months_since_first = 1 THEN user_id END) as month_1,
    COUNT(DISTINCT CASE WHEN months_since_first = 2 THEN user_id END) as month_2,
    COUNT(DISTINCT CASE WHEN months_since_first = 3 THEN user_id END) as month_3
FROM (
    SELECT
        o.user_id,
        MIN(o.created_at) OVER (PARTITION BY o.user_id) as first_order,
        EXTRACT(MONTH FROM AGE(o.created_at,
            MIN(o.created_at) OVER (PARTITION BY o.user_id))) as months_since_first
    FROM orders o
    WHERE o.status = 'completed'
) cohort_data
GROUP BY DATE_TRUNC('month', first_order)
ORDER BY cohort_month DESC;

-- Query 10: Shipping performance metrics
SELECT
    shipping_method,
    COUNT(*) as total_shipments,
    AVG(EXTRACT(DAY FROM (shipped_at - order_date))) as avg_processing_days,
    AVG(EXTRACT(DAY FROM (delivered_at - shipped_at))) as avg_transit_days,
    AVG(EXTRACT(DAY FROM (delivered_at - order_date))) as avg_total_days,
    SUM(CASE WHEN delivered_at <= estimated_delivery THEN 1 ELSE 0 END) * 100.0 / COUNT(*) as on_time_pct
FROM orders
WHERE status = 'delivered'
    AND shipped_at IS NOT NULL
    AND delivered_at IS NOT NULL
GROUP BY shipping_method
ORDER BY total_shipments DESC;
