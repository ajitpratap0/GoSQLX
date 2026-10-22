-- Window functions and analytics
SELECT OrderId, CustomerId, Total, ROW_NUMBER() OVER (PARTITION BY CustomerId ORDER BY OrderDate DESC) AS rn FROM dbo.Orders;
SELECT Name, Dept, Salary, RANK() OVER (PARTITION BY Dept ORDER BY Salary DESC) AS rk, DENSE_RANK() OVER (ORDER BY Salary DESC) AS drk, NTILE(4) OVER (ORDER BY Salary) AS quartile FROM HR.Employees;
SELECT OrderDate, Total, SUM(Total) OVER (ORDER BY OrderDate ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS RunningTotal FROM dbo.Orders;
SELECT OrderDate, Total, AVG(Total) OVER (ORDER BY OrderDate ROWS BETWEEN 6 PRECEDING AND CURRENT ROW) AS MovAvg7 FROM dbo.Orders;
SELECT OrderDate, Total, LAG(Total, 1, 0) OVER (ORDER BY OrderDate) AS Prev, LEAD(Total) OVER (ORDER BY OrderDate) AS NextTotal FROM dbo.Orders;
SELECT Dept, Name, FIRST_VALUE(Name) OVER (PARTITION BY Dept ORDER BY Salary DESC) AS TopEarner, LAST_VALUE(Name) OVER (PARTITION BY Dept ORDER BY Salary DESC ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) AS Lowest FROM HR.Employees;
SELECT Name, Salary, PERCENT_RANK() OVER (ORDER BY Salary) AS pr, CUME_DIST() OVER (ORDER BY Salary) AS cd FROM HR.Employees;
SELECT DISTINCT Dept, PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY Salary) OVER (PARTITION BY Dept) AS MedianSalary FROM HR.Employees;
SELECT Id, COUNT(*) OVER () AS TotalRows, COUNT(*) OVER (PARTITION BY Status) AS StatusRows FROM dbo.Tickets;
SELECT * FROM (SELECT *, ROW_NUMBER() OVER (PARTITION BY Email ORDER BY CreatedAt) AS rn FROM dbo.Customers) d WHERE d.rn > 1;
SELECT SUM(Amount) OVER w AS S, AVG(Amount) OVER w AS A FROM dbo.Sales WINDOW w AS (PARTITION BY Region ORDER BY SaleDate);
WITH Ranked AS (SELECT ProductId, CategoryId, Price, ROW_NUMBER() OVER (PARTITION BY CategoryId ORDER BY Price DESC) AS rn FROM dbo.Products) SELECT ProductId, CategoryId, Price FROM Ranked WHERE rn <= 3;
WITH Daily AS (SELECT CAST(CreatedAt AS DATE) AS D, COUNT(*) AS C FROM dbo.Orders GROUP BY CAST(CreatedAt AS DATE)) SELECT D, C, SUM(C) OVER (ORDER BY D) AS Cumulative, C - LAG(C) OVER (ORDER BY D) AS Delta FROM Daily;
WITH gaps AS (SELECT Id, Id - ROW_NUMBER() OVER (ORDER BY Id) AS grp FROM dbo.Seq) SELECT MIN(Id) AS StartId, MAX(Id) AS EndId FROM gaps GROUP BY grp;
SELECT CustomerId, MAX(CASE WHEN rn = 1 THEN OrderId END) AS LastOrder FROM (SELECT CustomerId, OrderId, ROW_NUMBER() OVER (PARTITION BY CustomerId ORDER BY OrderDate DESC) AS rn FROM dbo.Orders) t GROUP BY CustomerId;
SELECT Region, Amount, Amount * 100.0 / SUM(Amount) OVER (PARTITION BY Region) AS PctOfRegion FROM dbo.Sales;
SELECT OrderId, Total, SUM(Total) OVER (PARTITION BY CustomerId ORDER BY OrderDate RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS CustRunning FROM dbo.Orders;
