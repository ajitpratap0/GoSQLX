-- UNPIVOT operator (SQL Server-specific)
-- Complexity: Complex
-- Tests: UNPIVOT for column-to-row transformation
SELECT product, region, sales FROM (
    SELECT product, north_sales, south_sales, east_sales, west_sales
    FROM regional_sales
) AS SourceTable
UNPIVOT (
    sales FOR region IN (north_sales, south_sales, east_sales, west_sales)
) AS UnpivotTable;
