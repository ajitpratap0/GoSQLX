-- Aggregation with GROUP BY and HAVING
-- Complexity: Medium
-- Tests: COUNT, SUM, AVG, GROUP BY, HAVING
SELECT
    category_id,
    COUNT(*) as product_count,
    AVG(price) as avg_price,
    SUM(stock) as total_stock
FROM products
GROUP BY category_id
HAVING COUNT(*) > 5;
