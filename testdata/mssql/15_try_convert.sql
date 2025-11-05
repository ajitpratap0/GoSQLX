-- TRY_CONVERT function (SQL Server-specific)
-- Complexity: Medium
-- Tests: TRY_CONVERT for safe type conversion
SELECT
    id,
    TRY_CONVERT(INT, string_value) as int_value,
    TRY_CONVERT(DATETIME, date_string) as date_value
FROM data_table;
