-- Scenario: BI / reporting queries over an orders schema
SELECT c.region, strftime('%Y', o.ordered_at) AS yr, count(DISTINCT o.id) AS orders, sum(oi.qty * oi.unit_price) AS revenue
FROM orders o
JOIN customers c ON c.id = o.customer_id
JOIN order_items oi ON oi.order_id = o.id
JOIN products p ON p.id = oi.product_id
LEFT JOIN refunds r ON r.order_id = o.id
WHERE o.status NOT IN ('cancelled', 'draft') AND r.id IS NULL
GROUP BY c.region, yr
HAVING revenue > 1000
ORDER BY yr DESC, revenue DESC
LIMIT 100;
SELECT p.category, p.name, sum(oi.qty) AS units FROM products p LEFT JOIN order_items oi ON oi.product_id = p.id GROUP BY p.id ORDER BY units DESC NULLS LAST LIMIT 10;
SELECT date(ordered_at) AS day, count(*) FROM orders WHERE ordered_at >= date('now', '-30 days') GROUP BY day ORDER BY day;
SELECT customer_id, min(ordered_at) AS first_order, max(ordered_at) AS last_order, julianday(max(ordered_at)) - julianday(min(ordered_at)) AS span_days FROM orders GROUP BY customer_id;
SELECT CASE WHEN total < 50 THEN 'small' WHEN total < 500 THEN 'medium' ELSE 'large' END AS bucket, count(*) AS n, round(avg(total), 2) AS avg_total FROM orders GROUP BY bucket;
SELECT c.id, c.name, (SELECT count(*) FROM orders o WHERE o.customer_id = c.id) AS n_orders, (SELECT max(total) FROM orders o WHERE o.customer_id = c.id) AS biggest FROM customers c WHERE c.created_at BETWEEN '2024-01-01' AND '2024-12-31';
SELECT product_id FROM order_items GROUP BY product_id HAVING sum(qty) > (SELECT avg(q) FROM (SELECT sum(qty) AS q FROM order_items GROUP BY product_id));
SELECT a.customer_id, b.customer_id FROM orders a JOIN orders b ON a.id < b.id AND a.customer_id = b.customer_id AND abs(julianday(a.ordered_at) - julianday(b.ordered_at)) < 1;
SELECT o.id FROM orders o WHERE o.id IN (SELECT order_id FROM order_items WHERE product_id IN (SELECT id FROM products WHERE category = 'books'));
SELECT customer_id FROM orders WHERE status = 'paid' EXCEPT SELECT customer_id FROM refunds;
SELECT customer_id FROM orders WHERE total > 100 INTERSECT SELECT customer_id FROM orders WHERE status = 'paid' ORDER BY 1;
SELECT id, name FROM customers UNION ALL SELECT id, name FROM archived_customers ORDER BY name LIMIT 10 OFFSET 5;
SELECT 'orders' AS t, count(*) FROM orders UNION ALL SELECT 'customers', count(*) FROM customers UNION ALL SELECT 'products', count(*) FROM products;
SELECT coalesce(sum(total), 0) AS rev, count(*) FILTER (WHERE status = 'paid') AS paid FROM orders WHERE ordered_at >= :from AND ordered_at < :to;
SELECT * FROM orders WHERE customer_id = $cid AND status = @status;
SELECT * FROM orders WHERE id = ?1 OR id = ?2;
SELECT p.name, round(100.0 * sum(oi.qty * oi.unit_price) / (SELECT sum(qty * unit_price) FROM order_items), 2) AS share FROM products p JOIN order_items oi ON oi.product_id = p.id GROUP BY p.id ORDER BY share DESC;
SELECT cast(strftime('%m', ordered_at) AS INTEGER) AS m, sum(total) FROM orders GROUP BY m;
SELECT o.* FROM orders AS o INNER JOIN (SELECT customer_id, max(ordered_at) AS mx FROM orders GROUP BY customer_id) AS latest ON latest.customer_id = o.customer_id AND latest.mx = o.ordered_at;
SELECT count(*) AS "Total Orders", sum(total) AS "Total Revenue" FROM orders;
SELECT t1.a AS "x.y" FROM t t1 WHERE t1.a <> '';
