-- TPC-DS Query 42: Monthly item sales by year
SELECT
    dt.d_year,
    item.i_category_id,
    item.i_category,
    SUM(ss_ext_sales_price) AS total_sales
FROM
    date_dim dt
    JOIN store_sales ON dt.d_date_sk = ss_sold_date_sk
    JOIN item ON ss_item_sk = i_item_sk
WHERE
    i_manager_id = 1
    AND dt.d_moy = 11
    AND dt.d_year = 2000
GROUP BY
    dt.d_year, item.i_category_id, item.i_category
ORDER BY
    total_sales DESC, dt.d_year, item.i_category_id, item.i_category
LIMIT 100;
