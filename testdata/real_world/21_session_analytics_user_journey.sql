-- User session analytics and journey tracking
-- Complexity: Complex
-- Tests: Window functions, sessionization, user journey analysis
WITH session_events AS (
    SELECT
        user_id,
        event_timestamp,
        event_type,
        page_url,
        LAG(event_timestamp) OVER (PARTITION BY user_id ORDER BY event_timestamp) as prev_event_time,
        CASE
            WHEN event_timestamp - LAG(event_timestamp) OVER (PARTITION BY user_id ORDER BY event_timestamp) > INTERVAL '30 minutes'
                OR LAG(event_timestamp) OVER (PARTITION BY user_id ORDER BY event_timestamp) IS NULL
            THEN 1
            ELSE 0
        END as is_new_session
    FROM user_events
    WHERE event_timestamp >= CURRENT_DATE - INTERVAL '7 days'
),
sessions_numbered AS (
    SELECT
        *,
        SUM(is_new_session) OVER (PARTITION BY user_id ORDER BY event_timestamp) as session_number
    FROM session_events
),
session_metrics AS (
    SELECT
        user_id,
        session_number,
        MIN(event_timestamp) as session_start,
        MAX(event_timestamp) as session_end,
        EXTRACT(EPOCH FROM (MAX(event_timestamp) - MIN(event_timestamp))) / 60 as session_duration_minutes,
        COUNT(*) as event_count,
        COUNT(DISTINCT page_url) as pages_viewed,
        STRING_AGG(page_url, ' -> ' ORDER BY event_timestamp) as user_journey,
        MAX(CASE WHEN event_type = 'purchase' THEN 1 ELSE 0 END) as converted
    FROM sessions_numbered
    GROUP BY user_id, session_number
)
SELECT
    u.id,
    u.email,
    sm.session_start,
    sm.session_end,
    ROUND(sm.session_duration_minutes, 2) as session_duration_minutes,
    sm.event_count,
    sm.pages_viewed,
    sm.user_journey,
    sm.converted,
    CASE
        WHEN sm.session_duration_minutes < 1 THEN 'Bounce'
        WHEN sm.session_duration_minutes < 5 AND sm.pages_viewed <= 2 THEN 'Quick Visit'
        WHEN sm.converted = 1 THEN 'Converted'
        WHEN sm.session_duration_minutes >= 10 OR sm.pages_viewed >= 5 THEN 'Engaged'
        ELSE 'Browsing'
    END as session_category
FROM session_metrics sm
INNER JOIN users u ON sm.user_id = u.id
ORDER BY sm.session_start DESC;
