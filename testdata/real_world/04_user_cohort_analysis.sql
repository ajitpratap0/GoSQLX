-- User cohort retention analysis
-- Complexity: Complex
-- Tests: CTEs, date manipulation, pivot-like aggregation, cohort analysis
WITH user_cohorts AS (
    SELECT
        user_id,
        DATE_TRUNC('month', MIN(created_at)) as cohort_month
    FROM orders
    GROUP BY user_id
),
cohort_activity AS (
    SELECT
        uc.cohort_month,
        DATE_TRUNC('month', o.created_at) as activity_month,
        COUNT(DISTINCT o.user_id) as active_users,
        EXTRACT(MONTH FROM AGE(o.created_at, uc.cohort_month)) as months_since_signup
    FROM user_cohorts uc
    INNER JOIN orders o ON uc.user_id = o.user_id
    GROUP BY uc.cohort_month, DATE_TRUNC('month', o.created_at)
)
SELECT
    cohort_month,
    COUNT(DISTINCT user_id) as cohort_size,
    SUM(CASE WHEN months_since_signup = 0 THEN active_users ELSE 0 END) as month_0,
    SUM(CASE WHEN months_since_signup = 1 THEN active_users ELSE 0 END) as month_1,
    SUM(CASE WHEN months_since_signup = 2 THEN active_users ELSE 0 END) as month_2,
    SUM(CASE WHEN months_since_signup = 3 THEN active_users ELSE 0 END) as month_3
FROM cohort_activity ca
INNER JOIN user_cohorts uc ON ca.cohort_month = uc.cohort_month
GROUP BY cohort_month
ORDER BY cohort_month DESC;
