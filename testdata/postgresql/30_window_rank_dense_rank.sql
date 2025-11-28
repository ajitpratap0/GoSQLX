-- RANK and DENSE_RANK window functions
-- Complexity: Complex
-- Tests: RANK, DENSE_RANK comparison
SELECT
    name,
    score,
    RANK() OVER (ORDER BY score DESC) as rank,
    DENSE_RANK() OVER (ORDER BY score DESC) as dense_rank
FROM test_results;
