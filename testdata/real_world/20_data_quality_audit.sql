-- Data quality audit report
-- Complexity: Complex
-- Tests: Multiple CTEs, NULL analysis, data validation, statistical analysis
WITH table_stats AS (
    SELECT
        'users' as table_name,
        COUNT(*) as total_records,
        COUNT(DISTINCT id) as unique_ids,
        SUM(CASE WHEN email IS NULL OR email = '' THEN 1 ELSE 0 END) as missing_email,
        SUM(CASE WHEN created_at IS NULL THEN 1 ELSE 0 END) as missing_created_at,
        SUM(CASE WHEN updated_at < created_at THEN 1 ELSE 0 END) as invalid_dates,
        SUM(CASE WHEN email NOT LIKE '%@%' THEN 1 ELSE 0 END) as invalid_email_format
    FROM users
    UNION ALL
    SELECT
        'orders' as table_name,
        COUNT(*) as total_records,
        COUNT(DISTINCT id) as unique_ids,
        SUM(CASE WHEN customer_id IS NULL THEN 1 ELSE 0 END) as missing_customer_id,
        SUM(CASE WHEN order_date IS NULL THEN 1 ELSE 0 END) as missing_order_date,
        SUM(CASE WHEN total < 0 THEN 1 ELSE 0 END) as negative_totals,
        SUM(CASE WHEN status NOT IN ('pending', 'completed', 'cancelled') THEN 1 ELSE 0 END) as invalid_status
    FROM orders
),
orphaned_records AS (
    SELECT
        'order_items' as table_name,
        'orphaned_orders' as issue_type,
        COUNT(*) as issue_count
    FROM order_items oi
    LEFT JOIN orders o ON oi.order_id = o.id
    WHERE o.id IS NULL
    UNION ALL
    SELECT
        'orders' as table_name,
        'orphaned_customers' as issue_type,
        COUNT(*) as issue_count
    FROM orders o
    LEFT JOIN users u ON o.customer_id = u.id
    WHERE u.id IS NULL
),
duplicate_records AS (
    SELECT
        'users' as table_name,
        'duplicate_emails' as issue_type,
        COUNT(*) - COUNT(DISTINCT email) as issue_count
    FROM users
    WHERE email IS NOT NULL
)
SELECT
    table_name,
    'row_count' as metric,
    total_records as value,
    NULL as issue_description
FROM table_stats
UNION ALL
SELECT
    table_name,
    'duplicate_ids' as metric,
    total_records - unique_ids as value,
    'Records with duplicate IDs' as issue_description
FROM table_stats
WHERE total_records > unique_ids
UNION ALL
SELECT
    table_name,
    issue_type as metric,
    issue_count as value,
    'Orphaned foreign key references' as issue_description
FROM orphaned_records
WHERE issue_count > 0
UNION ALL
SELECT
    table_name,
    issue_type as metric,
    issue_count as value,
    'Duplicate email addresses' as issue_description
FROM duplicate_records
WHERE issue_count > 0
ORDER BY table_name, metric;
