-- SQL Server MERGE statement (upsert)
-- Complexity: Complex
-- Tests: MERGE statement with WHEN MATCHED/NOT MATCHED
MERGE INTO target_table AS target
USING source_table AS source
ON target.id = source.id
WHEN MATCHED THEN
    UPDATE SET target.value = source.value
WHEN NOT MATCHED THEN
    INSERT (id, value) VALUES (source.id, source.value);
