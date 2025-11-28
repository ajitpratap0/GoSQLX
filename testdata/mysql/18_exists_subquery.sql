-- EXISTS subquery
-- Complexity: Medium
-- Tests: EXISTS with correlated subquery
SELECT c.name, c.email
FROM customers c
WHERE EXISTS (
    SELECT 1 FROM orders o WHERE o.customer_id = c.id AND o.total > 500
);
