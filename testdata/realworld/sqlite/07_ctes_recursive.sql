-- Scenario: CTE chains, recursive trees and calendars
WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM cnt WHERE x < 100) SELECT x FROM cnt;
WITH RECURSIVE tree(id, parent_id, name, depth) AS (
  SELECT id, parent_id, name, 0 FROM categories WHERE parent_id IS NULL
  UNION ALL
  SELECT c.id, c.parent_id, c.name, t.depth + 1 FROM categories c JOIN tree t ON c.parent_id = t.id
)
SELECT printf('%.*c%s', depth * 2, ' ', name) AS label FROM tree ORDER BY depth, name;
WITH RECURSIVE dates(d) AS (
  VALUES (date('2024-01-01'))
  UNION ALL
  SELECT date(d, '+1 day') FROM dates WHERE d < date('2024-01-31')
)
SELECT d, strftime('%w', d) AS dow FROM dates;
WITH RECURSIVE path(id, trail) AS (
  SELECT id, name FROM categories WHERE parent_id IS NULL
  UNION
  SELECT c.id, p.trail || ' > ' || c.name FROM categories c JOIN path p ON c.parent_id = p.id
) SELECT * FROM path ORDER BY trail LIMIT 50;
WITH a AS (SELECT 1 AS n), b AS (SELECT n + 1 AS n FROM a), c AS (SELECT n + 1 AS n FROM b), d AS (SELECT n + 1 AS n FROM c) SELECT * FROM d;
WITH monthly AS (
  SELECT strftime('%Y-%m', posted_at) AS ym, account_id, sum(amount) AS total FROM transactions GROUP BY ym, account_id
), ranked AS (
  SELECT ym, account_id, total, rank() OVER (PARTITION BY ym ORDER BY total DESC) AS rk FROM monthly
), top3 AS (
  SELECT * FROM ranked WHERE rk <= 3
)
SELECT t.ym, a.name, t.total FROM top3 t JOIN accounts a ON a.id = t.account_id ORDER BY t.ym, t.rk;
WITH cte(a, b) AS (SELECT 1, 2) SELECT a + b FROM cte;
WITH cte AS MATERIALIZED (SELECT * FROM transactions WHERE amount > 100) SELECT count(*) FROM cte;
WITH cte AS NOT MATERIALIZED (SELECT * FROM transactions) SELECT * FROM cte WHERE id = 1;
WITH del AS (SELECT id FROM notes WHERE pinned = 0) DELETE FROM notes WHERE id IN (SELECT id FROM del);
WITH src(k, v) AS (VALUES ('a', 1), ('b', 2)) INSERT INTO settings (key, value) SELECT k, v FROM src ON CONFLICT (key) DO UPDATE SET value = excluded.value;
WITH t AS (SELECT account_id, max(posted_at) AS last FROM transactions GROUP BY account_id) UPDATE accounts SET archived = 1 WHERE id IN (SELECT account_id FROM t WHERE last < date('now', '-1 year'));
SELECT * FROM (SELECT * FROM (SELECT * FROM (SELECT id, amount FROM transactions WHERE amount > 0) WHERE amount < 1000) ORDER BY amount) LIMIT 5;
SELECT a.id FROM accounts a WHERE a.balance > (SELECT avg(balance) FROM accounts WHERE currency = a.currency) AND EXISTS (SELECT 1 FROM transactions t WHERE t.account_id = a.id AND t.amount > (SELECT avg(amount) FROM transactions));
