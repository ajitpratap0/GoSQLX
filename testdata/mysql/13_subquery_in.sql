-- Subquery with IN operator
-- Complexity: Medium
-- Tests: Subquery, IN clause
SELECT name, email
FROM customers
WHERE id IN (
    SELECT DISTINCT customer_id FROM orders WHERE total > 1000
);
