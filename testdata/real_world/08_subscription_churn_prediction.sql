-- Subscription churn risk analysis
-- Complexity: Complex
-- Tests: Window functions, date calculations, multiple CTEs, risk scoring
WITH subscription_activity AS (
    SELECT
        user_id,
        subscription_type,
        start_date,
        end_date,
        COALESCE(end_date, CURRENT_DATE) as effective_end_date,
        EXTRACT(DAY FROM COALESCE(end_date, CURRENT_DATE) - start_date) as subscription_days
    FROM subscriptions
),
user_engagement AS (
    SELECT
        user_id,
        COUNT(*) as login_count,
        MAX(created_at) as last_login,
        EXTRACT(DAY FROM CURRENT_DATE - MAX(created_at)) as days_since_last_login
    FROM user_sessions
    WHERE created_at >= CURRENT_DATE - INTERVAL '30 days'
    GROUP BY user_id
),
support_tickets AS (
    SELECT
        user_id,
        COUNT(*) as ticket_count,
        SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved_count
    FROM support_tickets
    WHERE created_at >= CURRENT_DATE - INTERVAL '30 days'
    GROUP BY user_id
)
SELECT
    u.id,
    u.email,
    sa.subscription_type,
    sa.subscription_days,
    COALESCE(ue.login_count, 0) as monthly_logins,
    COALESCE(ue.days_since_last_login, 999) as days_since_last_login,
    COALESCE(st.ticket_count, 0) as support_tickets,
    CASE
        WHEN COALESCE(ue.days_since_last_login, 999) > 14 THEN 40
        WHEN COALESCE(ue.days_since_last_login, 999) > 7 THEN 20
        ELSE 0
    END +
    CASE
        WHEN COALESCE(ue.login_count, 0) = 0 THEN 30
        WHEN COALESCE(ue.login_count, 0) < 5 THEN 15
        ELSE 0
    END +
    CASE
        WHEN COALESCE(st.ticket_count, 0) > 5 THEN 20
        WHEN COALESCE(st.ticket_count, 0) > 2 THEN 10
        ELSE 0
    END as churn_risk_score,
    CASE
        WHEN (COALESCE(ue.days_since_last_login, 999) > 14 OR COALESCE(ue.login_count, 0) = 0) THEN 'HIGH'
        WHEN (COALESCE(ue.days_since_last_login, 999) > 7 OR COALESCE(ue.login_count, 0) < 5) THEN 'MEDIUM'
        ELSE 'LOW'
    END as churn_risk_category
FROM users u
INNER JOIN subscription_activity sa ON u.id = sa.user_id
LEFT JOIN user_engagement ue ON u.id = ue.user_id
LEFT JOIN support_tickets st ON u.id = st.user_id
WHERE sa.end_date IS NULL OR sa.end_date > CURRENT_DATE
ORDER BY churn_risk_score DESC;
