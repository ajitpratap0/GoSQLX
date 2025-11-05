-- IIF function (SQL Server inline IF)
-- Complexity: Simple
-- Tests: IIF function
SELECT
    name,
    salary,
    IIF(salary > 50000, 'High', 'Low') as salary_category
FROM employees;
