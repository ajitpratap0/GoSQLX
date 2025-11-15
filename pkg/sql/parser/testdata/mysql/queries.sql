-- MySQL Real-World Queries
-- These queries represent common production patterns from actual MySQL databases

-- Query 1: Basic SELECT with backtick identifiers
SELECT `id`, `name`, `email` FROM `users` WHERE `active` = 1;

-- Query 2: INSERT with multiple rows
INSERT INTO products (name, price, category_id, created_at)
VALUES
    ('Product 1', 29.99, 1, NOW()),
    ('Product 2', 49.99, 1, NOW()),
    ('Product 3', 79.99, 2, NOW());

-- Query 3: UPDATE with LIMIT
UPDATE users
SET last_login = NOW()
WHERE active = 1
ORDER BY last_login ASC
LIMIT 1000;

-- Query 4: JOIN with GROUP BY
SELECT
    c.id,
    c.name as category_name,
    COUNT(p.id) as product_count,
    AVG(p.price) as avg_price,
    MIN(p.price) as min_price,
    MAX(p.price) as max_price
FROM categories c
LEFT JOIN products p ON c.id = p.category_id
GROUP BY c.id, c.name
HAVING product_count > 0
ORDER BY product_count DESC;

-- Query 5: Complex JOIN with multiple tables
SELECT
    o.id,
    o.order_date,
    u.username,
    p.name as product_name,
    oi.quantity,
    oi.price
FROM orders o
INNER JOIN users u ON o.user_id = u.id
INNER JOIN order_items oi ON o.id = oi.order_id
INNER JOIN products p ON oi.product_id = p.id
WHERE o.status = 'completed'
    AND o.order_date >= DATE_SUB(NOW(), INTERVAL 30 DAY);

-- Query 6: Subquery in SELECT
SELECT
    id,
    username,
    email,
    (SELECT COUNT(*) FROM orders WHERE user_id = users.id) as order_count
FROM users
WHERE active = 1;

-- Query 7: UNION ALL for combining data
SELECT id, name, 'active' as status FROM active_users
UNION ALL
SELECT id, name, 'inactive' as status FROM inactive_users
ORDER BY name;

-- Query 8: DELETE with JOIN
DELETE u
FROM user_sessions u
INNER JOIN users ON u.user_id = users.id
WHERE users.deleted_at IS NOT NULL;

-- Query 9: Aggregate with DISTINCT
SELECT
    category_id,
    COUNT(DISTINCT user_id) as unique_buyers,
    COUNT(*) as total_orders,
    SUM(total) as revenue
FROM orders o
INNER JOIN order_items oi ON o.id = oi.order_id
WHERE o.order_date >= '2024-01-01'
GROUP BY category_id;

-- Query 10: Complex WHERE with IN
SELECT *
FROM products
WHERE category_id IN (1, 2, 3, 5, 8)
    AND price BETWEEN 10 AND 100
    AND stock_quantity > 0
ORDER BY name;

-- Query 11: Self-join for hierarchy
SELECT
    c1.id,
    c1.name,
    c2.name as parent_name
FROM categories c1
LEFT JOIN categories c2 ON c1.parent_id = c2.id
ORDER BY c1.name;

-- Query 12: INSERT SELECT
INSERT INTO archived_orders (order_id, user_id, total, order_date)
SELECT id, user_id, total, order_date
FROM orders
WHERE order_date < DATE_SUB(NOW(), INTERVAL 1 YEAR)
    AND status = 'completed';

-- Query 13: UPDATE with subquery
UPDATE products
SET featured = 1
WHERE id IN (
    SELECT product_id
    FROM order_items
    GROUP BY product_id
    HAVING COUNT(*) > 100
);

-- Query 14: Multiple aggregates
SELECT
    DATE(order_date) as order_day,
    COUNT(*) as total_orders,
    COUNT(DISTINCT user_id) as unique_customers,
    SUM(total) as daily_revenue,
    AVG(total) as avg_order_value,
    MAX(total) as largest_order
FROM orders
WHERE order_date >= DATE_SUB(NOW(), INTERVAL 7 DAY)
GROUP BY DATE(order_date)
ORDER BY order_day DESC;

-- Query 15: Nested subquery
SELECT
    category_id,
    name,
    price
FROM products
WHERE price > (
    SELECT AVG(price)
    FROM products p2
    WHERE p2.category_id = products.category_id
)
ORDER BY category_id, price DESC;

-- Query 16: LEFT JOIN with IS NULL check
SELECT u.id, u.username, u.email
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
WHERE o.id IS NULL
    AND u.created_at < DATE_SUB(NOW(), INTERVAL 6 MONTH);

-- Query 17: REPLACE statement
REPLACE INTO user_preferences (user_id, preference_key, preference_value)
VALUES (123, 'theme', 'dark');

-- Query 18: ON DUPLICATE KEY UPDATE
INSERT INTO product_views (product_id, view_count, last_viewed)
VALUES (456, 1, NOW())
ON DUPLICATE KEY UPDATE
    view_count = view_count + 1,
    last_viewed = NOW();

-- Query 19: Complex JOIN with OR conditions
SELECT DISTINCT u.id, u.username
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
LEFT JOIN wishlists w ON u.id = w.user_id
WHERE o.order_date >= '2024-01-01'
    OR w.created_at >= '2024-01-01';

-- Query 20: GROUP BY with ROLLUP
SELECT
    category_id,
    product_id,
    SUM(quantity) as total_quantity
FROM order_items
GROUP BY category_id, product_id WITH ROLLUP;
