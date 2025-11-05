-- Social network graph analysis (friend connections)
-- Complexity: Complex
-- Tests: Recursive CTE, graph traversal, network metrics
WITH RECURSIVE friend_network AS (
    SELECT
        user_id,
        friend_id,
        1 as degree,
        ARRAY[user_id, friend_id] as path
    FROM friendships
    WHERE user_id = 12345
    UNION
    SELECT
        fn.user_id,
        f.friend_id,
        fn.degree + 1,
        fn.path || f.friend_id
    FROM friend_network fn
    INNER JOIN friendships f ON fn.friend_id = f.user_id
    WHERE fn.degree < 3
        AND NOT f.friend_id = ANY(fn.path)
),
network_stats AS (
    SELECT
        friend_id as connected_user_id,
        MIN(degree) as shortest_path,
        COUNT(*) as connection_count
    FROM friend_network
    GROUP BY friend_id
)
SELECT
    u.id,
    u.name,
    u.email,
    ns.shortest_path as degrees_of_separation,
    ns.connection_count as num_paths,
    COUNT(DISTINCT f.friend_id) as mutual_friends
FROM network_stats ns
INNER JOIN users u ON ns.connected_user_id = u.id
LEFT JOIN friendships f ON ns.connected_user_id = f.user_id
    AND f.friend_id IN (SELECT friend_id FROM friendships WHERE user_id = 12345)
GROUP BY u.id, u.name, u.email, ns.shortest_path, ns.connection_count
ORDER BY ns.shortest_path, ns.connection_count DESC;
