-- TPC-DS Query 52: Year-to-date sales by brand
SELECT dt.d_year, item.i_brand_id AS brand_id, item.i_brand AS brand,
    SUM(ss_ext_sales_price) AS ext_price
FROM date_dim dt
    JOIN store_sales ON dt.d_date_sk = ss_sold_date_sk
    JOIN item ON ss_item_sk = i_item_sk
WHERE i_manager_id = 1 AND dt.d_moy = 11 AND dt.d_year = 2000
GROUP BY dt.d_year, item.i_brand, item.i_brand_id
ORDER BY dt.d_year, ext_price DESC, brand_id
LIMIT 100;
