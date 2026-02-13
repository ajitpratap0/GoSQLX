-- TPC-DS Query 13: Store sales by demographics
SELECT
    AVG(ss_quantity) AS avg_qty,
    AVG(ss_ext_sales_price) AS avg_sales,
    AVG(ss_ext_wholesale_cost) AS avg_wholesale,
    SUM(ss_ext_wholesale_cost) AS sum_wholesale
FROM
    store_sales
    JOIN store ON s_store_sk = ss_store_sk
    JOIN customer_demographics ON cd_demo_sk = ss_cdemo_sk
    JOIN household_demographics ON hd_demo_sk = ss_hdemo_sk
    JOIN customer_address ON ca_address_sk = ss_addr_sk
    JOIN date_dim ON d_date_sk = ss_sold_date_sk
WHERE
    (
        cd_marital_status = 'M' AND cd_education_status = 'Advanced Degree'
        AND ss_sales_price BETWEEN 100.00 AND 150.00
        AND hd_dep_count = 3
    )
    OR (
        cd_marital_status = 'S' AND cd_education_status = 'College'
        AND ss_sales_price BETWEEN 50.00 AND 100.00
        AND hd_dep_count = 1
    )
    OR (
        cd_marital_status = 'W' AND cd_education_status = '2 yr Degree'
        AND ss_sales_price BETWEEN 150.00 AND 200.00
        AND hd_dep_count = 1
    )
    AND d_year = 2001
    AND (
        (ca_country = 'United States' AND ca_state IN ('TX', 'OH', 'TX'))
        OR (ca_country = 'United States' AND ca_state IN ('OR', 'NM', 'KY'))
        OR (ca_country = 'United States' AND ca_state IN ('VA', 'TX', 'MS'))
    );
