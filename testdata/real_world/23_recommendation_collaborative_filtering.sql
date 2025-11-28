-- Collaborative filtering product recommendations
-- Complexity: Complex
-- Tests: Self-joins, similarity calculations, ranking, filtering
WITH user_product_matrix AS (
    SELECT
        user_id,
        product_id,
        SUM(quantity) as purchase_count,
        SUM(quantity * price) as total_spent
    FROM order_items oi
    INNER JOIN orders o ON oi.order_id = o.id
    WHERE o.status = 'completed'
        AND o.order_date >= CURRENT_DATE - INTERVAL '180 days'
    GROUP BY user_id, product_id
),
user_similarities AS (
    SELECT
        u1.user_id as user_a,
        u2.user_id as user_b,
        COUNT(DISTINCT u1.product_id) as common_products,
        SUM(u1.purchase_count * u2.purchase_count) as similarity_score
    FROM user_product_matrix u1
    INNER JOIN user_product_matrix u2 ON u1.product_id = u2.product_id AND u1.user_id < u2.user_id
    GROUP BY u1.user_id, u2.user_id
    HAVING COUNT(DISTINCT u1.product_id) >= 3
),
similar_users_ranked AS (
    SELECT
        user_a,
        user_b,
        similarity_score,
        ROW_NUMBER() OVER (PARTITION BY user_a ORDER BY similarity_score DESC) as similarity_rank
    FROM user_similarities
),
recommendations AS (
    SELECT
        sur.user_a as target_user,
        upm.product_id,
        SUM(upm.purchase_count * sur.similarity_score) as recommendation_score,
        COUNT(DISTINCT sur.user_b) as similar_user_count,
        AVG(upm.total_spent) as avg_spent_by_similar_users
    FROM similar_users_ranked sur
    INNER JOIN user_product_matrix upm ON sur.user_b = upm.user_id
    WHERE sur.similarity_rank <= 10
        AND NOT EXISTS (
            SELECT 1 FROM user_product_matrix target
            WHERE target.user_id = sur.user_a AND target.product_id = upm.product_id
        )
    GROUP BY sur.user_a, upm.product_id
)
SELECT
    r.target_user,
    p.id as product_id,
    p.name as product_name,
    p.category,
    ROUND(r.recommendation_score, 2) as score,
    r.similar_user_count,
    ROUND(r.avg_spent_by_similar_users, 2) as avg_spent,
    ROW_NUMBER() OVER (PARTITION BY r.target_user ORDER BY r.recommendation_score DESC) as recommendation_rank
FROM recommendations r
INNER JOIN products p ON r.product_id = p.id
WHERE p.active = true
    AND p.stock > 0
ORDER BY r.target_user, recommendation_rank
LIMIT 100;
