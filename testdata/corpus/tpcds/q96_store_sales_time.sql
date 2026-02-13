-- TPC-DS Query 96: Store sales by time
SELECT COUNT(*) AS cnt
FROM store_sales
    JOIN household_demographics ON ss_hdemo_sk = hd_demo_sk
    JOIN time_dim ON ss_sold_time_sk = t_time_sk
    JOIN store ON ss_store_sk = s_store_sk
WHERE t_hour = 20 AND t_minute >= 30
    AND hd_dep_count = 7 AND s_store_name = 'ese'
ORDER BY cnt
LIMIT 100;
