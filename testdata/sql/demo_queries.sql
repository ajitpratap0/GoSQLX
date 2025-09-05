-- Simple query
SELECT name, email FROM users WHERE active = true;

-- Complex query with JOIN
SELECT u.name, o.order_date, p.product_name 
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
INNER JOIN products p ON o.product_id = p.id
WHERE u.created_at > '2023-01-01'
ORDER BY o.order_date DESC
LIMIT 10;

-- Window function query
SELECT 
    name,
    salary,
    ROW_NUMBER() OVER (PARTITION BY department ORDER BY salary DESC) as rank,
    LAG(salary, 1) OVER (ORDER BY hire_date) as prev_salary
FROM employees;
