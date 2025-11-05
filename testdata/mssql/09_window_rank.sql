-- Window functions RANK and DENSE_RANK
-- Complexity: Complex
-- Tests: RANK, DENSE_RANK window functions
SELECT
    student_name,
    score,
    RANK() OVER (ORDER BY score DESC) as rank,
    DENSE_RANK() OVER (ORDER BY score DESC) as dense_rank,
    NTILE(4) OVER (ORDER BY score DESC) as quartile
FROM exam_results;
