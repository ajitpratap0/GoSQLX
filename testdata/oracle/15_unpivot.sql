-- Oracle UNPIVOT operator
-- Complexity: Complex
-- Tests: UNPIVOT for column-to-row transformation
SELECT product, region, sales FROM regional_sales
UNPIVOT (
    sales FOR region IN (north_sales AS 'North', south_sales AS 'South', east_sales AS 'East', west_sales AS 'West')
);
