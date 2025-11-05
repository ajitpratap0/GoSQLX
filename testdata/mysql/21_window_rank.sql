-- Window function RANK (MySQL 8.0+)
-- Complexity: Complex
-- Tests: RANK and DENSE_RANK
SELECT
    student_name,
    score,
    RANK() OVER (ORDER BY score DESC) as rank,
    DENSE_RANK() OVER (ORDER BY score DESC) as dense_rank
FROM exam_results;
