-- Oracle ROWNUM pseudo-column
-- Complexity: Simple
-- Tests: ROWNUM for limiting results
SELECT * FROM users WHERE ROWNUM <= 10;
