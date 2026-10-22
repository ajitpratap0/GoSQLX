-- Scenario: analytics dashboard with window functions
SELECT id, amount, sum(amount) OVER (ORDER BY posted_at) AS running FROM transactions;
SELECT account_id, posted_at, amount, row_number() OVER (PARTITION BY account_id ORDER BY posted_at DESC) AS rn FROM transactions;
SELECT *, rank() OVER w AS r, dense_rank() OVER w AS dr FROM transactions WINDOW w AS (PARTITION BY account_id ORDER BY amount DESC);
SELECT id, lag(amount, 1, 0) OVER (PARTITION BY account_id ORDER BY posted_at) AS prev, lead(amount) OVER (PARTITION BY account_id ORDER BY posted_at) AS nxt FROM transactions;
SELECT id, avg(amount) OVER (ORDER BY posted_at ROWS BETWEEN 6 PRECEDING AND CURRENT ROW) AS ma7 FROM transactions;
SELECT id, sum(amount) OVER (ORDER BY id RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) FROM transactions;
SELECT id, sum(amount) OVER (ORDER BY id GROUPS BETWEEN 1 PRECEDING AND 1 FOLLOWING) FROM transactions;
SELECT id, first_value(amount) OVER (PARTITION BY account_id ORDER BY posted_at ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) FROM transactions;
SELECT id, last_value(amount) OVER (PARTITION BY account_id ORDER BY posted_at) FROM transactions;
SELECT id, nth_value(amount, 2) OVER (ORDER BY posted_at) FROM transactions;
SELECT id, ntile(4) OVER (ORDER BY amount) AS quartile, percent_rank() OVER (ORDER BY amount) AS pr, cume_dist() OVER (ORDER BY amount) AS cd FROM transactions;
SELECT id, sum(amount) FILTER (WHERE amount > 0) OVER (PARTITION BY account_id) AS pos_total FROM transactions;
SELECT count(*) FILTER (WHERE amount < 0) AS refunds, count(*) AS total FROM transactions;
SELECT id, sum(amount) OVER (ORDER BY id ROWS BETWEEN 1 PRECEDING AND 1 FOLLOWING EXCLUDE CURRENT ROW) FROM transactions;
SELECT id, sum(amount) OVER (w1 ROWS 2 PRECEDING) FROM transactions WINDOW w1 AS (PARTITION BY account_id ORDER BY id);
WITH ranked AS (
  SELECT account_id, amount, row_number() OVER (PARTITION BY account_id ORDER BY amount DESC) AS rn FROM transactions
)
SELECT account_id, amount FROM ranked WHERE rn <= 3;
SELECT strftime('%Y-%m', posted_at) AS month, sum(amount) AS total, sum(sum(amount)) OVER (ORDER BY strftime('%Y-%m', posted_at)) AS cumulative FROM transactions GROUP BY month;
SELECT group_concat(name, ', ') FROM accounts;
SELECT account_id, group_concat(DISTINCT memo) FROM transactions GROUP BY account_id;
SELECT account_id, group_concat(memo, '; ' ) FROM transactions GROUP BY account_id HAVING count(*) > 2 ORDER BY account_id;
SELECT total(amount), min(amount), max(amount), avg(amount) FROM transactions;
SELECT string_agg(name, ',') FROM accounts;
