-- Resource utilization and capacity planning
-- Complexity: Complex
-- Tests: Time series, capacity calculations, forecasting data prep
WITH hourly_usage AS (
    SELECT
        resource_id,
        DATE_TRUNC('hour', timestamp) as usage_hour,
        AVG(cpu_percent) as avg_cpu,
        MAX(cpu_percent) as peak_cpu,
        AVG(memory_percent) as avg_memory,
        MAX(memory_percent) as peak_memory,
        AVG(disk_io_mbps) as avg_disk_io,
        MAX(disk_io_mbps) as peak_disk_io
    FROM resource_metrics
    WHERE timestamp >= CURRENT_TIMESTAMP - INTERVAL '7 days'
    GROUP BY resource_id, DATE_TRUNC('hour', timestamp)
),
resource_stats AS (
    SELECT
        r.id,
        r.name,
        r.type,
        r.max_capacity,
        AVG(hu.avg_cpu) as avg_cpu_utilization,
        MAX(hu.peak_cpu) as max_cpu_utilization,
        AVG(hu.avg_memory) as avg_memory_utilization,
        MAX(hu.peak_memory) as max_memory_utilization,
        AVG(hu.avg_disk_io) as avg_disk_io,
        MAX(hu.peak_disk_io) as max_disk_io,
        STDDEV(hu.avg_cpu) as cpu_volatility,
        COUNT(CASE WHEN hu.peak_cpu > 80 THEN 1 END) as hours_over_80pct
    FROM resources r
    LEFT JOIN hourly_usage hu ON r.id = hu.resource_id
    GROUP BY r.id, r.name, r.type, r.max_capacity
)
SELECT
    id,
    name,
    type,
    ROUND(avg_cpu_utilization, 2) as avg_cpu_pct,
    ROUND(max_cpu_utilization, 2) as max_cpu_pct,
    ROUND(avg_memory_utilization, 2) as avg_memory_pct,
    ROUND(max_memory_utilization, 2) as max_memory_pct,
    hours_over_80pct,
    CASE
        WHEN max_cpu_utilization > 90 OR max_memory_utilization > 90 THEN 'CRITICAL - Scale Now'
        WHEN max_cpu_utilization > 80 OR max_memory_utilization > 80 THEN 'WARNING - Plan Scale'
        WHEN avg_cpu_utilization > 70 OR avg_memory_utilization > 70 THEN 'MONITOR - Approaching Limit'
        ELSE 'OK'
    END as capacity_status,
    CASE
        WHEN avg_cpu_utilization > 70 THEN
            ROUND((100 - avg_cpu_utilization) / (avg_cpu_utilization / 100), 1)
        ELSE NULL
    END as estimated_capacity_left_pct
FROM resource_stats
ORDER BY max_cpu_utilization DESC, max_memory_utilization DESC;
