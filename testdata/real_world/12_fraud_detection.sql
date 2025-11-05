-- Fraud detection with anomaly scoring
-- Complexity: Complex
-- Tests: Window functions, statistical functions, complex scoring logic
WITH user_transaction_patterns AS (
    SELECT
        user_id,
        AVG(amount) as avg_transaction_amount,
        STDDEV(amount) as stddev_transaction_amount,
        COUNT(*) as transaction_count,
        AVG(EXTRACT(HOUR FROM created_at)) as avg_transaction_hour
    FROM transactions
    WHERE created_at >= CURRENT_DATE - INTERVAL '90 days'
    GROUP BY user_id
),
recent_transactions AS (
    SELECT
        t.*,
        utp.avg_transaction_amount,
        utp.stddev_transaction_amount,
        utp.avg_transaction_hour,
        ABS(t.amount - utp.avg_transaction_amount) / NULLIF(utp.stddev_transaction_amount, 0) as amount_z_score,
        ABS(EXTRACT(HOUR FROM t.created_at) - utp.avg_transaction_hour) as hour_deviation,
        COUNT(*) OVER (PARTITION BY t.user_id, DATE(t.created_at)) as transactions_today,
        LAG(t.created_at) OVER (PARTITION BY t.user_id ORDER BY t.created_at) as prev_transaction_time
    FROM transactions t
    INNER JOIN user_transaction_patterns utp ON t.user_id = utp.user_id
    WHERE t.created_at >= CURRENT_DATE - INTERVAL '7 days'
)
SELECT
    id,
    user_id,
    amount,
    merchant,
    created_at,
    CASE
        WHEN amount_z_score > 3 THEN 20
        WHEN amount_z_score > 2 THEN 10
        ELSE 0
    END +
    CASE
        WHEN transactions_today > 10 THEN 25
        WHEN transactions_today > 5 THEN 15
        ELSE 0
    END +
    CASE
        WHEN hour_deviation > 6 THEN 15
        ELSE 0
    END +
    CASE
        WHEN EXTRACT(EPOCH FROM (created_at - prev_transaction_time)) < 60 THEN 20
        ELSE 0
    END as fraud_risk_score,
    CASE
        WHEN amount_z_score > 3 OR transactions_today > 10 THEN 'HIGH'
        WHEN amount_z_score > 2 OR transactions_today > 5 OR hour_deviation > 6 THEN 'MEDIUM'
        ELSE 'LOW'
    END as risk_level
FROM recent_transactions
WHERE amount_z_score > 2 OR transactions_today > 5 OR hour_deviation > 6
ORDER BY fraud_risk_score DESC;
