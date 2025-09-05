-- Performance test queries for analyzer benchmarking
-- This file contains queries that test various performance scenarios

-- Complex JOIN with multiple tables
SELECT 
    u.name,
    u.email,
    o.order_date,
    p.product_name,
    p.price
FROM users u
INNER JOIN orders o ON u.id = o.user_id
INNER JOIN products p ON o.product_id = p.id
WHERE u.active = true 
    AND o.order_date > '2023-01-01'
    AND p.price > 10.00
ORDER BY o.order_date DESC;

-- Window function query
SELECT 
    name,
    salary,
    ROW_NUMBER() OVER (PARTITION BY department ORDER BY salary DESC) as rank,
    LAG(salary, 1) OVER (ORDER BY hire_date) as prev_salary
FROM employees;

-- Function in WHERE clause (performance issue)
SELECT name FROM users WHERE UPPER(name) = 'TEST';

-- Query without WHERE clause (performance issue)
SELECT name, email FROM users;