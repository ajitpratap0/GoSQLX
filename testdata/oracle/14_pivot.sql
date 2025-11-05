-- Oracle PIVOT operator
-- Complexity: Complex
-- Tests: PIVOT for row-to-column transformation
SELECT * FROM (
    SELECT product, region, sales
    FROM sales_data
)
PIVOT (
    SUM(sales) FOR region IN ('North' AS north, 'South' AS south, 'East' AS east, 'West' AS west)
);
