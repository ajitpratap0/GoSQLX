-- T-SQL scripts written without semicolons, as SSMS and sqlcmd accept them:
-- statements end where the next one starts and GO separates batches.
USE [Sales]
GO
SET NOCOUNT ON
SET XACT_ABORT ON
GO
IF OBJECT_ID(N'dbo.OrderAudit', N'U') IS NOT NULL
    DROP TABLE dbo.OrderAudit
CREATE TABLE dbo.OrderAudit (
    AuditId INT IDENTITY(1, 1) NOT NULL PRIMARY KEY,
    OrderId INT NOT NULL,
    Action NVARCHAR(20) NOT NULL,
    ChangedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
)
CREATE INDEX IX_OrderAudit_OrderId ON dbo.OrderAudit (OrderId)
GO
BEGIN TRANSACTION
UPDATE dbo.Orders SET Status = N'Shipped' WHERE OrderId = 42
INSERT INTO dbo.OrderAudit (OrderId, Action) VALUES (42, N'ship')
COMMIT TRANSACTION
GO
SET NOCOUNT ON
SELECT COUNT(*) AS OpenOrders FROM dbo.Orders WHERE Status = N'Open'
SET NOCOUNT OFF
GO
DECLARE @Pending TABLE (OrderId INT PRIMARY KEY, Total DECIMAL(18, 2))
INSERT INTO @Pending (OrderId, Total)
SELECT o.OrderId, o.Total FROM dbo.Orders AS o WHERE o.Status = N'Pending'
UPDATE @Pending SET Total = Total * 1.1 WHERE Total < 100
DELETE FROM @Pending WHERE Total > 10000
SELECT p.OrderId, p.Total FROM @Pending AS p JOIN dbo.Customers AS c ON c.CustomerId = p.OrderId
GO
DECLARE @Cutoff DATE = DATEADD(DAY, -30, GETDATE())
DELETE FROM dbo.Sessions WHERE LastSeen < @Cutoff
PRINT N'Deleted ' + CAST(@@ROWCOUNT AS NVARCHAR(20)) + N' sessions'
GO
UPDATE dbo.Inventory SET Quantity = Quantity - 1 WHERE ProductId = 7
IF @@ROWCOUNT = 0
    PRINT N'No inventory row for product 7'
GO
ALTER TABLE dbo.Orders NOCHECK CONSTRAINT ALL
ALTER TABLE dbo.Orders ADD ShippedAt DATETIME2 NULL
ALTER TABLE dbo.Orders CHECK CONSTRAINT ALL
GO
TRUNCATE TABLE dbo.StagingOrders
INSERT INTO dbo.StagingOrders (OrderId, Total) SELECT OrderId, Total FROM dbo.Orders WHERE Total > 0
EXEC dbo.usp_ProcessStaging @BatchSize = 500
GO
BEGIN TRY
    BEGIN TRANSACTION
    UPDATE dbo.Accounts SET Balance = Balance - 100 WHERE AccountId = 1
    UPDATE dbo.Accounts SET Balance = Balance + 100 WHERE AccountId = 2
    COMMIT TRANSACTION
END TRY
BEGIN CATCH
    ROLLBACK TRANSACTION
    THROW
END CATCH
GO
CREATE OR ALTER PROCEDURE dbo.usp_ArchiveOrders
    @Before DATE
AS
BEGIN
    SET NOCOUNT ON
    INSERT INTO dbo.OrdersArchive (OrderId, Total) SELECT OrderId, Total FROM dbo.Orders WHERE OrderDate < @Before
    DELETE FROM dbo.Orders WHERE OrderDate < @Before
END
GO
EXEC dbo.usp_ArchiveOrders @Before = '2024-01-01'
SELECT TOP (10) OrderId, Total FROM dbo.OrdersArchive ORDER BY OrderId DESC
GO
WITH Ranked AS (
    SELECT CustomerId, Total, ROW_NUMBER() OVER (PARTITION BY CustomerId ORDER BY Total DESC) AS rn
    FROM dbo.Orders
)
SELECT CustomerId, Total FROM Ranked WHERE rn = 1
SELECT 1 AS Done
GO
IF OBJECT_ID(N'tempdb..#Totals') IS NOT NULL DROP TABLE #Totals
SELECT CustomerId, SUM(Total) AS Total INTO #Totals FROM dbo.Orders GROUP BY CustomerId
IF EXISTS (SELECT 1 FROM #Totals WHERE Total > 100000)
    PRINT N'Large customers found'
ELSE
    PRINT N'No large customers'
DROP TABLE #Totals
GO
DECLARE @Retries INT = 0
WHILE @Retries < 3
BEGIN
    SET @Retries = @Retries + 1
    WAITFOR DELAY '00:00:01'
END
SELECT @Retries AS Retries
GO
BEGIN TRANSACTION
DELETE FROM dbo.Carts WHERE UpdatedAt < DATEADD(DAY, -7, GETDATE())
IF @@ERROR <> 0 ROLLBACK TRANSACTION ELSE COMMIT TRANSACTION
GO
GRANT SELECT, INSERT ON dbo.OrderAudit TO [ReportingRole]
DENY DELETE ON dbo.OrderAudit TO [ReportingRole]
REVOKE UPDATE ON dbo.Orders FROM [LegacyApp]
SELECT name FROM sys.database_principals WHERE type = N'R'
GO
