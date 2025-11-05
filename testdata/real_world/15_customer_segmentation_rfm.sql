-- RFM (Recency, Frequency, Monetary) customer segmentation
-- Complexity: Complex
-- Tests: Window functions, NTILE, scoring algorithms, segmentation
WITH customer_rfm_raw AS (
    SELECT
        customer_id,
        MAX(order_date) as last_order_date,
        COUNT(*) as order_frequency,
        SUM(total) as monetary_value,
        EXTRACT(DAY FROM CURRENT_DATE - MAX(order_date)) as recency_days
    FROM orders
    WHERE status = 'completed'
        AND order_date >= CURRENT_DATE - INTERVAL '365 days'
    GROUP BY customer_id
),
customer_rfm_scores AS (
    SELECT
        customer_id,
        recency_days,
        order_frequency,
        monetary_value,
        NTILE(5) OVER (ORDER BY recency_days) as r_score,
        NTILE(5) OVER (ORDER BY order_frequency DESC) as f_score,
        NTILE(5) OVER (ORDER BY monetary_value DESC) as m_score
    FROM customer_rfm_raw
),
customer_rfm_segments AS (
    SELECT
        *,
        (r_score + f_score + m_score) / 3.0 as rfm_score,
        CASE
            WHEN r_score >= 4 AND f_score >= 4 AND m_score >= 4 THEN 'Champions'
            WHEN r_score >= 3 AND f_score >= 3 AND m_score >= 3 THEN 'Loyal Customers'
            WHEN r_score >= 4 AND f_score <= 2 THEN 'New Customers'
            WHEN r_score <= 2 AND f_score >= 4 THEN 'At Risk'
            WHEN r_score <= 2 AND f_score <= 2 THEN 'Lost Customers'
            WHEN m_score >= 4 THEN 'Big Spenders'
            ELSE 'Regular'
        END as segment
    FROM customer_rfm_scores
)
SELECT
    c.id,
    c.name,
    c.email,
    rfm.recency_days,
    rfm.order_frequency,
    rfm.monetary_value,
    rfm.r_score,
    rfm.f_score,
    rfm.m_score,
    rfm.rfm_score,
    rfm.segment
FROM customers c
INNER JOIN customer_rfm_segments rfm ON c.id = rfm.customer_id
ORDER BY rfm.rfm_score DESC, rfm.monetary_value DESC;
