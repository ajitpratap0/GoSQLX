-- PostgreSQL Real-World Queries
-- These queries represent common production patterns from actual PostgreSQL databases

-- Query 1: Simple user lookup with WHERE clause
SELECT id, username, email, created_at
FROM users
WHERE active = true AND deleted_at IS NULL;

-- Query 2: JOIN with aggregate
SELECT u.id, u.username, COUNT(o.id) as order_count, SUM(o.total) as total_spent
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
WHERE u.created_at > '2023-01-01'
GROUP BY u.id, u.username
HAVING COUNT(o.id) > 5
ORDER BY total_spent DESC
LIMIT 100;

-- Query 3: CTE for complex hierarchy
WITH RECURSIVE category_tree AS (
    SELECT id, name, parent_id, 0 as level
    FROM categories
    WHERE parent_id IS NULL
    UNION ALL
    SELECT c.id, c.name, c.parent_id, ct.level + 1
    FROM categories c
    INNER JOIN category_tree ct ON c.parent_id = ct.id
)
SELECT * FROM category_tree ORDER BY level, name;

-- Query 4: Window function for ranking
SELECT
    product_id,
    product_name,
    category_id,
    price,
    ROW_NUMBER() OVER (PARTITION BY category_id ORDER BY price DESC) as price_rank,
    AVG(price) OVER (PARTITION BY category_id) as category_avg_price
FROM products
WHERE active = true;

-- Query 5: Multiple JOINs with filtering
SELECT
    o.id as order_id,
    o.order_date,
    u.username,
    u.email,
    p.product_name,
    oi.quantity,
    oi.unit_price,
    oi.quantity * oi.unit_price as line_total
FROM orders o
INNER JOIN users u ON o.user_id = u.id
INNER JOIN order_items oi ON o.id = oi.order_id
INNER JOIN products p ON oi.product_id = p.id
WHERE o.order_date >= '2024-01-01'
    AND o.status = 'completed'
ORDER BY o.order_date DESC, o.id;

-- Query 6: Subquery in WHERE clause
SELECT id, username, email
FROM users
WHERE id IN (
    SELECT DISTINCT user_id
    FROM orders
    WHERE order_date > '2024-01-01'
        AND total > 1000
);

-- Query 7: INSERT with returning
INSERT INTO users (username, email, password_hash, created_at)
VALUES ('newuser', 'newuser@example.com', 'hash123', NOW());

-- Query 8: UPDATE with JOIN
UPDATE products
SET stock_quantity = stock_quantity - oi.quantity
FROM order_items oi
WHERE products.id = oi.product_id
    AND oi.order_id = 12345;

-- Query 9: DELETE with subquery
DELETE FROM sessions
WHERE user_id IN (
    SELECT id FROM users WHERE deleted_at IS NOT NULL
);

-- Query 10: Complex analytics query
SELECT
    DATE_TRUNC('month', order_date) as month,
    COUNT(DISTINCT user_id) as unique_customers,
    COUNT(*) as total_orders,
    SUM(total) as revenue,
    AVG(total) as avg_order_value
FROM orders
WHERE order_date >= '2023-01-01'
    AND status = 'completed'
GROUP BY DATE_TRUNC('month', order_date)
ORDER BY month DESC;

-- Query 11: Window function with LAG
SELECT
    date,
    revenue,
    LAG(revenue, 1) OVER (ORDER BY date) as prev_day_revenue,
    revenue - LAG(revenue, 1) OVER (ORDER BY date) as daily_change
FROM daily_revenue
WHERE date >= '2024-01-01'
ORDER BY date;

-- Query 12: Self-join for comparisons
SELECT
    e1.id as employee_id,
    e1.name as employee_name,
    e1.salary,
    e2.name as manager_name,
    e2.salary as manager_salary
FROM employees e1
LEFT JOIN employees e2 ON e1.manager_id = e2.id
WHERE e1.department = 'Engineering';

-- Query 13: UNION for combining results
SELECT id, email, 'customer' as type FROM customers
UNION
SELECT id, email, 'employee' as type FROM employees
ORDER BY email;

-- Query 14: Complex WHERE with multiple conditions
SELECT *
FROM products
WHERE (category_id = 1 AND price < 100)
    OR (category_id = 2 AND price < 200)
    OR (featured = true AND stock_quantity > 0)
ORDER BY created_at DESC
LIMIT 50;

-- Query 15: Nested CTEs
WITH monthly_sales AS (
    SELECT
        DATE_TRUNC('month', order_date) as month,
        SUM(total) as monthly_total
    FROM orders
    WHERE status = 'completed'
    GROUP BY DATE_TRUNC('month', order_date)
),
sales_with_growth AS (
    SELECT
        month,
        monthly_total,
        LAG(monthly_total) OVER (ORDER BY month) as prev_month,
        (monthly_total - LAG(monthly_total) OVER (ORDER BY month)) /
            NULLIF(LAG(monthly_total) OVER (ORDER BY month), 0) * 100 as growth_pct
    FROM monthly_sales
)
SELECT * FROM sales_with_growth ORDER BY month DESC;
