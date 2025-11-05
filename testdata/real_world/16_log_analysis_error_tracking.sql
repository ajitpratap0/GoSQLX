-- Application log analysis and error tracking
-- Complexity: Complex
-- Tests: String operations, aggregations, pattern matching, time series
WITH error_logs AS (
    SELECT
        DATE_TRUNC('hour', timestamp) as error_hour,
        log_level,
        error_type,
        error_message,
        user_id,
        request_path,
        COUNT(*) as error_count
    FROM application_logs
    WHERE log_level IN ('ERROR', 'FATAL')
        AND timestamp >= CURRENT_TIMESTAMP - INTERVAL '24 hours'
    GROUP BY DATE_TRUNC('hour', timestamp), log_level, error_type, error_message, user_id, request_path
),
error_trends AS (
    SELECT
        error_hour,
        error_type,
        error_message,
        SUM(error_count) as total_errors,
        COUNT(DISTINCT user_id) as affected_users,
        STRING_AGG(DISTINCT request_path, ', ') as affected_paths,
        LAG(SUM(error_count)) OVER (PARTITION BY error_type ORDER BY error_hour) as prev_hour_errors,
        AVG(SUM(error_count)) OVER (PARTITION BY error_type ORDER BY error_hour ROWS BETWEEN 5 PRECEDING AND 1 PRECEDING) as avg_previous_hours
    FROM error_logs
    GROUP BY error_hour, error_type, error_message
)
SELECT
    error_hour,
    error_type,
    error_message,
    total_errors,
    affected_users,
    affected_paths,
    prev_hour_errors,
    total_errors - prev_hour_errors as hourly_change,
    CASE
        WHEN avg_previous_hours > 0 THEN
            ROUND(((total_errors - avg_previous_hours) / avg_previous_hours * 100), 2)
        ELSE NULL
    END as trend_pct,
    CASE
        WHEN total_errors > avg_previous_hours * 3 THEN 'CRITICAL'
        WHEN total_errors > avg_previous_hours * 2 THEN 'WARNING'
        ELSE 'NORMAL'
    END as alert_level
FROM error_trends
WHERE total_errors > 0
ORDER BY total_errors DESC, error_hour DESC;
