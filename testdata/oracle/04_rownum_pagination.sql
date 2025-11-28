-- Oracle pagination using ROWNUM (pre-12c)
-- Complexity: Medium
-- Tests: ROWNUM-based pagination pattern
SELECT * FROM (
    SELECT a.*, ROWNUM rnum FROM (
        SELECT * FROM users ORDER BY created_at DESC
    ) a WHERE ROWNUM <= 30
) WHERE rnum > 20;
