-- Real-time seat availability for booking system
-- Complexity: Complex
-- Tests: Recursive CTE, date generation, complex availability logic
WITH RECURSIVE event_dates AS (
    SELECT
        id as event_id,
        start_date as event_date,
        end_date
    FROM events
    WHERE active = true
    UNION ALL
    SELECT
        event_id,
        event_date + INTERVAL '1 day',
        end_date
    FROM event_dates
    WHERE event_date < end_date
),
seat_inventory AS (
    SELECT
        ed.event_id,
        ed.event_date,
        s.section_id,
        s.seat_number,
        s.price_tier,
        CASE
            WHEN b.id IS NOT NULL THEN 'booked'
            WHEN h.id IS NOT NULL AND h.expires_at > CURRENT_TIMESTAMP THEN 'held'
            ELSE 'available'
        END as status
    FROM event_dates ed
    CROSS JOIN seats s
    LEFT JOIN bookings b ON ed.event_id = b.event_id
        AND ed.event_date = b.event_date
        AND s.seat_number = b.seat_number
    LEFT JOIN seat_holds h ON ed.event_id = h.event_id
        AND ed.event_date = h.event_date
        AND s.seat_number = h.seat_number
        AND h.expires_at > CURRENT_TIMESTAMP
)
SELECT
    e.name as event_name,
    si.event_date,
    sec.name as section_name,
    si.price_tier,
    COUNT(*) as total_seats,
    SUM(CASE WHEN si.status = 'available' THEN 1 ELSE 0 END) as available_seats,
    SUM(CASE WHEN si.status = 'held' THEN 1 ELSE 0 END) as held_seats,
    SUM(CASE WHEN si.status = 'booked' THEN 1 ELSE 0 END) as booked_seats,
    ROUND(100.0 * SUM(CASE WHEN si.status = 'booked' THEN 1 ELSE 0 END) / COUNT(*), 2) as booking_percentage
FROM seat_inventory si
INNER JOIN events e ON si.event_id = e.id
INNER JOIN sections sec ON si.section_id = sec.id
GROUP BY e.name, si.event_date, sec.name, si.price_tier
HAVING SUM(CASE WHEN si.status = 'available' THEN 1 ELSE 0 END) > 0
ORDER BY e.name, si.event_date, sec.name, si.price_tier;
