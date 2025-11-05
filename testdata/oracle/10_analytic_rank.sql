-- Oracle RANK and DENSE_RANK
-- Complexity: Complex
-- Tests: Ranking functions with gaps
SELECT
    student_name,
    score,
    RANK() OVER (ORDER BY score DESC) as rank,
    DENSE_RANK() OVER (ORDER BY score DESC) as dense_rank
FROM exam_results;
