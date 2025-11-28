-- UNION combining multiple result sets
-- Complexity: Medium
-- Tests: UNION, ORDER BY on combined result
SELECT id, name, 'customer' as type FROM customers
UNION
SELECT id, name, 'supplier' as type FROM suppliers
ORDER BY name;
