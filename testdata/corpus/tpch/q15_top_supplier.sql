-- TPC-H Query 15: Top Supplier
-- Note: Uses a CTE instead of CREATE VIEW for portability
WITH revenue AS (
    SELECT
        l_suppkey AS supplier_no,
        SUM(l_extendedprice * (1 - l_discount)) AS total_revenue
    FROM
        lineitem
    WHERE
        l_shipdate >= DATE '1996-01-01'
        AND l_shipdate < DATE '1996-01-01' + INTERVAL '3 MONTH'
    GROUP BY
        l_suppkey
)
SELECT
    s_suppkey,
    s_name,
    s_address,
    s_phone,
    total_revenue
FROM
    supplier,
    revenue
WHERE
    s_suppkey = supplier_no
    AND total_revenue = (
        SELECT MAX(total_revenue) FROM revenue
    )
ORDER BY
    s_suppkey;
