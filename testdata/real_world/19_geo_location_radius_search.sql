-- Geospatial radius search for nearby locations
-- Complexity: Complex
-- Tests: Mathematical functions, distance calculations, geospatial queries
WITH user_location AS (
    SELECT
        40.7128 as user_lat,
        -74.0060 as user_lon,
        5.0 as search_radius_km
),
store_distances AS (
    SELECT
        s.id,
        s.name,
        s.address,
        s.latitude,
        s.longitude,
        s.store_type,
        6371 * 2 * ASIN(SQRT(
            POWER(SIN((RADIANS(s.latitude) - RADIANS(ul.user_lat)) / 2), 2) +
            COS(RADIANS(ul.user_lat)) * COS(RADIANS(s.latitude)) *
            POWER(SIN((RADIANS(s.longitude) - RADIANS(ul.user_lon)) / 2), 2)
        )) as distance_km
    FROM stores s
    CROSS JOIN user_location ul
    WHERE s.active = true
),
nearby_stores_with_inventory AS (
    SELECT
        sd.*,
        COUNT(DISTINCT i.product_id) as products_in_stock,
        SUM(i.quantity) as total_inventory_units,
        AVG(r.rating) as avg_rating,
        COUNT(DISTINCT r.id) as review_count
    FROM store_distances sd
    LEFT JOIN inventory i ON sd.id = i.store_id AND i.quantity > 0
    LEFT JOIN reviews r ON sd.id = r.store_id
    GROUP BY sd.id, sd.name, sd.address, sd.latitude, sd.longitude, sd.store_type, sd.distance_km
)
SELECT
    id,
    name,
    address,
    store_type,
    ROUND(distance_km, 2) as distance_km,
    products_in_stock,
    total_inventory_units,
    COALESCE(ROUND(avg_rating, 1), 0) as avg_rating,
    review_count,
    RANK() OVER (ORDER BY distance_km) as distance_rank
FROM nearby_stores_with_inventory
WHERE distance_km <= (SELECT search_radius_km FROM user_location)
ORDER BY distance_km, avg_rating DESC NULLS LAST;
