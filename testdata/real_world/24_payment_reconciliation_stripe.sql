-- Payment gateway reconciliation (Stripe-style)
-- Complexity: Complex
-- Tests: FULL OUTER JOIN, date matching, money calculations, variance detection
WITH internal_transactions AS (
    SELECT
        transaction_id,
        order_id,
        payment_date,
        amount as internal_amount,
        status as internal_status,
        stripe_charge_id
    FROM payments
    WHERE payment_date >= CURRENT_DATE - INTERVAL '30 days'
),
stripe_charges AS (
    SELECT
        charge_id,
        created_date,
        amount / 100.0 as stripe_amount,
        status as stripe_status,
        fee_amount / 100.0 as stripe_fee,
        net_amount / 100.0 as stripe_net
    FROM stripe_webhook_charges
    WHERE created_date >= CURRENT_DATE - INTERVAL '30 days'
),
reconciliation AS (
    SELECT
        COALESCE(it.transaction_id, sc.charge_id) as transaction_id,
        it.order_id,
        it.stripe_charge_id,
        sc.charge_id as stripe_charge_id,
        it.payment_date,
        sc.created_date as stripe_date,
        it.internal_amount,
        sc.stripe_amount,
        sc.stripe_fee,
        sc.stripe_net,
        it.internal_status,
        sc.stripe_status,
        ABS(COALESCE(it.internal_amount, 0) - COALESCE(sc.stripe_amount, 0)) as amount_variance,
        CASE
            WHEN it.transaction_id IS NULL THEN 'Missing in Internal System'
            WHEN sc.charge_id IS NULL THEN 'Missing in Stripe'
            WHEN it.internal_status != sc.stripe_status THEN 'Status Mismatch'
            WHEN ABS(it.internal_amount - sc.stripe_amount) > 0.01 THEN 'Amount Mismatch'
            WHEN DATE(it.payment_date) != DATE(sc.created_date) THEN 'Date Mismatch'
            ELSE 'Matched'
        END as reconciliation_status
    FROM internal_transactions it
    FULL OUTER JOIN stripe_charges sc ON it.stripe_charge_id = sc.charge_id
)
SELECT
    transaction_id,
    order_id,
    stripe_charge_id,
    payment_date,
    stripe_date,
    internal_amount,
    stripe_amount,
    stripe_fee,
    stripe_net,
    internal_status,
    stripe_status,
    ROUND(amount_variance, 2) as variance,
    reconciliation_status
FROM reconciliation
WHERE reconciliation_status != 'Matched'
ORDER BY amount_variance DESC, payment_date DESC;
