-- Monthly revenue pivot with a default for missing sales.
SELECT * FROM monthly_sales PIVOT (SUM(amount) FOR sales_month IN (ANY ORDER BY sales_month) DEFAULT ON NULL (0)) AS revenue;

-- Department totals with nested grouping operations.
SELECT department, region, SUM(amount) FROM monthly_sales GROUP BY GROUPING SETS ((department), ROLLUP(region), CUBE(department, region), ());
