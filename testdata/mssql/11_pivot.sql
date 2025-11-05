-- PIVOT operator (SQL Server-specific)
-- Complexity: Complex
-- Tests: PIVOT for row-to-column transformation
SELECT * FROM (
    SELECT product, region, sales
    FROM sales_data
) AS SourceTable
PIVOT (
    SUM(sales) FOR region IN ([North], [South], [East], [West])
) AS PivotTable;
