-- dbt-style models (Jinja already rendered): staging, intermediate, marts
WITH source AS (SELECT * FROM raw.stripe.payments), renamed AS (SELECT id AS payment_id, orderid AS order_id, paymentmethod AS payment_method, status, amount / 100 AS amount, created AS created_at FROM source) SELECT * FROM renamed;
WITH customers AS (SELECT * FROM analytics.staging.stg_customers), orders AS (SELECT * FROM analytics.staging.stg_orders), customer_orders AS (SELECT customer_id, MIN(order_date) AS first_order, MAX(order_date) AS most_recent_order, COUNT(order_id) AS number_of_orders FROM orders GROUP BY customer_id), final AS (SELECT customers.customer_id, customers.first_name, customers.last_name, customer_orders.first_order, customer_orders.most_recent_order, COALESCE(customer_orders.number_of_orders, 0) AS number_of_orders FROM customers LEFT JOIN customer_orders USING (customer_id)) SELECT * FROM final;
CREATE OR REPLACE TABLE analytics.marts.fct_orders AS WITH orders AS (SELECT * FROM analytics.staging.stg_orders), payments AS (SELECT * FROM analytics.staging.stg_payments), order_payments AS (SELECT order_id, SUM(CASE WHEN payment_method = 'credit_card' THEN amount ELSE 0 END) AS credit_card_amount, SUM(CASE WHEN payment_method = 'bank_transfer' THEN amount ELSE 0 END) AS bank_transfer_amount, SUM(amount) AS total_amount FROM payments WHERE status = 'success' GROUP BY order_id) SELECT o.order_id, o.customer_id, o.order_date, op.credit_card_amount, op.bank_transfer_amount, op.total_amount AS amount FROM orders o LEFT JOIN order_payments op ON o.order_id = op.order_id;
CREATE OR REPLACE VIEW analytics.staging.stg_customers AS SELECT id AS customer_id, first_name, last_name FROM raw.jaffle_shop.customers;
SELECT date_day, COUNT(*) AS n FROM (SELECT DATEADD(day, ROW_NUMBER() OVER (ORDER BY SEQ4()) - 1, '2020-01-01'::date) AS date_day FROM TABLE(GENERATOR(ROWCOUNT => 1000))) GROUP BY 1;
SELECT MD5(CAST(COALESCE(CAST(customer_id AS VARCHAR), '') || '-' || COALESCE(CAST(order_id AS VARCHAR), '') AS VARCHAR)) AS surrogate_key, * FROM analytics.staging.stg_orders;
SELECT * FROM analytics.marts.fct_orders WHERE order_date > (SELECT MAX(order_date) FROM analytics.marts.fct_orders_incremental);
DELETE FROM analytics.marts.fct_orders_incremental WHERE (order_id) IN (SELECT order_id FROM analytics.marts.fct_orders_incremental__tmp);
INSERT INTO analytics.marts.fct_orders_incremental (order_id, customer_id, order_date) SELECT order_id, customer_id, order_date FROM analytics.marts.fct_orders_incremental__tmp;
SELECT COUNT(*) AS failures, COUNT(*) != 0 AS should_warn FROM (SELECT customer_id FROM analytics.marts.dim_customers WHERE customer_id IS NULL) dbt_internal_test;
SELECT customer_id AS unique_field, COUNT(*) AS n_records FROM analytics.marts.dim_customers WHERE customer_id IS NOT NULL GROUP BY customer_id HAVING COUNT(*) > 1;
SELECT a.*, b.* FROM (SELECT 1 AS id) a LEFT JOIN (SELECT 1 AS id) b ON a.id = b.id WHERE b.id IS NULL;
CREATE OR REPLACE TRANSIENT TABLE analytics.snapshots.orders_snapshot AS SELECT *, CURRENT_TIMESTAMP() AS dbt_valid_from, NULL::timestamp_ntz AS dbt_valid_to FROM analytics.staging.stg_orders;
SELECT order_id, status, LAG(status) OVER (PARTITION BY order_id ORDER BY updated_at) AS prev_status FROM analytics.staging.stg_order_events QUALIFY status != prev_status;
SELECT DATE_TRUNC('week', order_date)::date AS week_start, SUM(amount) AS weekly_amount, SUM(SUM(amount)) OVER (ORDER BY DATE_TRUNC('week', order_date)) AS cumulative FROM analytics.marts.fct_orders GROUP BY 1;
ALTER TABLE analytics.marts.fct_orders SWAP WITH analytics.marts.fct_orders__dbt_tmp;
DROP TABLE IF EXISTS analytics.marts.fct_orders__dbt_tmp CASCADE;
GRANT SELECT ON TABLE analytics.marts.fct_orders TO ROLE reporter;
