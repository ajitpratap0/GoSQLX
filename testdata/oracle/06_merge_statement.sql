-- Oracle MERGE statement (upsert)
-- Complexity: Complex
-- Tests: MERGE with MATCHED and NOT MATCHED
MERGE INTO target_table t
USING source_table s
ON (t.id = s.id)
WHEN MATCHED THEN
    UPDATE SET t.value = s.value, t.updated_at = SYSDATE
WHEN NOT MATCHED THEN
    INSERT (id, value, created_at) VALUES (s.id, s.value, SYSDATE);
