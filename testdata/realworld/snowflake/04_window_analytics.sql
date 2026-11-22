-- Window function analytics, QUALIFY, and ranking
SELECT id, customer_id, total, ROW_NUMBER() OVER (PARTITION BY customer_id ORDER BY total DESC) AS rn FROM orders;
SELECT * FROM orders QUALIFY ROW_NUMBER() OVER (PARTITION BY customer_id ORDER BY order_date DESC) = 1;
SELECT customer_id, order_date, total FROM orders QUALIFY RANK() OVER (PARTITION BY customer_id ORDER BY total DESC) <= 3;
SELECT * FROM events QUALIFY ROW_NUMBER() OVER (PARTITION BY event_id ORDER BY loaded_at DESC) = 1 ORDER BY event_id;
SELECT a, b, SUM(c) AS s FROM t GROUP BY a, b QUALIFY DENSE_RANK() OVER (PARTITION BY a ORDER BY SUM(c) DESC) = 1;
SELECT day, revenue, AVG(revenue) OVER (ORDER BY day ROWS BETWEEN 6 PRECEDING AND CURRENT ROW) AS ma7 FROM daily_revenue;
SELECT day, revenue, LAG(revenue, 7) OVER (ORDER BY day) AS last_week, LEAD(revenue) OVER (ORDER BY day) AS next_day FROM daily_revenue;
SELECT id, FIRST_VALUE(price) OVER (PARTITION BY sku ORDER BY ts) AS first_price, LAST_VALUE(price) OVER (PARTITION BY sku ORDER BY ts ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) AS last_price FROM prices;
SELECT id, NTILE(4) OVER (ORDER BY score) AS quartile, PERCENT_RANK() OVER (ORDER BY score) AS pr, CUME_DIST() OVER (ORDER BY score) AS cd FROM scores;
SELECT id, NTH_VALUE(amount, 2) OVER (PARTITION BY grp ORDER BY ts) AS second_amount FROM t;
SELECT id, RATIO_TO_REPORT(amount) OVER (PARTITION BY grp) AS share FROM t;
SELECT id, LAG(amount) IGNORE NULLS OVER (PARTITION BY grp ORDER BY ts) AS prev_non_null FROM t;
SELECT id, FIRST_VALUE(amount) IGNORE NULLS OVER (ORDER BY ts) AS fv FROM t;
WITH ranked AS (SELECT *, ROW_NUMBER() OVER (PARTITION BY dept ORDER BY salary DESC) AS rn FROM employees) SELECT * FROM ranked WHERE rn <= 3;
WITH dedup AS (SELECT * FROM raw_events QUALIFY ROW_NUMBER() OVER (PARTITION BY id ORDER BY updated_at DESC) = 1), enriched AS (SELECT d.*, u.email FROM dedup d LEFT JOIN users u ON u.id = d.user_id) SELECT * FROM enriched WHERE email IS NOT NULL;
SELECT *, SUM(x) OVER () AS total, x / NULLIF(SUM(x) OVER (), 0) AS pct FROM t;
SELECT MIN_BY(name, score) AS worst, MAX_BY(name, score) AS best FROM players;
SELECT ANY_VALUE(name) AS n, MODE(country) AS mode_country FROM customers GROUP BY segment;
