# GoSQLX Testing Helpers - Usage Guide

## Quick Start

### 1. Import the Package

```go
import (
    "testing"
    gosqlxtesting "github.com/ajitpratap0/GoSQLX/pkg/gosqlx/testing"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)
```

### 2. Basic Validation

```go
func TestSQLQueries(t *testing.T) {
    // Assert SQL is valid
    gosqlxtesting.AssertValidSQL(t, "SELECT * FROM users")

    // Assert SQL is invalid
    gosqlxtesting.AssertInvalidSQL(t, "SELECT FROM WHERE")
}
```

### 3. Test Table References

```go
func TestTableExtraction(t *testing.T) {
    gosqlxtesting.AssertTables(t,
        "SELECT * FROM users u JOIN orders o ON u.id = o.user_id",
        []string{"users", "orders"})
}
```

### 4. Test Column Selection

```go
func TestColumnExtraction(t *testing.T) {
    gosqlxtesting.AssertColumns(t,
        "SELECT id, name, email FROM users",
        []string{"id", "name", "email"})
}
```

## Real-World Example: Testing a User Repository

```go
package repository

import (
    "testing"
    gosqlxtesting "github.com/ajitpratap0/GoSQLX/pkg/gosqlx/testing"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// UserRepository contains SQL queries for user operations
type UserRepository struct {
    GetAllUsersQuery    string
    CreateUserQuery     string
    UpdateUserQuery     string
    DeleteUserQuery     string
}

func NewUserRepository() *UserRepository {
    return &UserRepository{
        GetAllUsersQuery: "SELECT id, name, email, active FROM users WHERE active = true ORDER BY created_at DESC",
        CreateUserQuery:  "INSERT INTO users (name, email, active) VALUES (?, ?, ?)",
        UpdateUserQuery:  "UPDATE users SET name = ?, email = ?, active = ? WHERE id = ?",
        DeleteUserQuery:  "DELETE FROM users WHERE id = ?",
    }
}

// Test the repository SQL queries
func TestUserRepository_Queries(t *testing.T) {
    repo := NewUserRepository()

    t.Run("GetAllUsersQuery", func(t *testing.T) {
        // Validate syntax
        gosqlxtesting.RequireValidSQL(t, repo.GetAllUsersQuery)

        // Verify it's a SELECT statement
        gosqlxtesting.AssertParsesTo(t, repo.GetAllUsersQuery, &ast.SelectStatement{})

        // Verify correct table
        gosqlxtesting.AssertTables(t, repo.GetAllUsersQuery, []string{"users"})

        // Verify all expected columns are selected
        gosqlxtesting.AssertColumns(t, repo.GetAllUsersQuery,
            []string{"id", "name", "email", "active"})
    })

    t.Run("CreateUserQuery", func(t *testing.T) {
        gosqlxtesting.RequireValidSQL(t, repo.CreateUserQuery)
        gosqlxtesting.AssertParsesTo(t, repo.CreateUserQuery, &ast.InsertStatement{})
        gosqlxtesting.AssertTables(t, repo.CreateUserQuery, []string{"users"})
    })

    t.Run("UpdateUserQuery", func(t *testing.T) {
        gosqlxtesting.RequireValidSQL(t, repo.UpdateUserQuery)
        gosqlxtesting.AssertParsesTo(t, repo.UpdateUserQuery, &ast.UpdateStatement{})
        gosqlxtesting.AssertTables(t, repo.UpdateUserQuery, []string{"users"})
    })

    t.Run("DeleteUserQuery", func(t *testing.T) {
        gosqlxtesting.RequireValidSQL(t, repo.DeleteUserQuery)
        gosqlxtesting.AssertParsesTo(t, repo.DeleteUserQuery, &ast.DeleteStatement{})
        gosqlxtesting.AssertTables(t, repo.DeleteUserQuery, []string{"users"})
    })
}
```

## Advanced Example: Testing Complex Analytics Queries

```go
package analytics

import (
    "testing"
    gosqlxtesting "github.com/ajitpratap0/GoSQLX/pkg/gosqlx/testing"
)

// AnalyticsQueries contains complex SQL for analytics
type AnalyticsQueries struct {
    UserOrderStats        string
    ProductPopularity     string
    MonthlyRevenue        string
}

func NewAnalyticsQueries() *AnalyticsQueries {
    return &AnalyticsQueries{
        UserOrderStats: `
            SELECT
                u.id,
                u.name,
                COUNT(o.id) as order_count,
                SUM(o.total) as total_spent,
                AVG(o.total) as avg_order_value
            FROM users u
            LEFT JOIN orders o ON u.id = o.user_id
            GROUP BY u.id, u.name
            HAVING COUNT(o.id) > 0
            ORDER BY total_spent DESC
        `,
        ProductPopularity: `
            SELECT
                p.id,
                p.name,
                p.category,
                COUNT(oi.id) as times_ordered,
                RANK() OVER (PARTITION BY p.category ORDER BY COUNT(oi.id) DESC) as category_rank
            FROM products p
            JOIN order_items oi ON p.id = oi.product_id
            GROUP BY p.id, p.name, p.category
        `,
        MonthlyRevenue: `
            WITH monthly_sales AS (
                SELECT
                    DATE_TRUNC('month', order_date) as month,
                    SUM(total) as revenue
                FROM orders
                WHERE order_date >= '2023-01-01'
                GROUP BY DATE_TRUNC('month', order_date)
            )
            SELECT
                month,
                revenue,
                LAG(revenue) OVER (ORDER BY month) as prev_month_revenue
            FROM monthly_sales
            ORDER BY month DESC
        `,
    }
}

func TestAnalyticsQueries(t *testing.T) {
    queries := NewAnalyticsQueries()

    t.Run("UserOrderStats", func(t *testing.T) {
        // Validate complex aggregation query
        gosqlxtesting.RequireValidSQL(t, queries.UserOrderStats)

        // Verify tables involved
        gosqlxtesting.AssertTables(t, queries.UserOrderStats,
            []string{"users", "orders"})

        // Verify base columns (aggregate functions are not extracted)
        gosqlxtesting.AssertColumns(t, queries.UserOrderStats,
            []string{"id", "name"})
    })

    t.Run("ProductPopularity", func(t *testing.T) {
        // Validate window function query
        gosqlxtesting.RequireValidSQL(t, queries.ProductPopularity)

        // Verify tables
        gosqlxtesting.AssertTables(t, queries.ProductPopularity,
            []string{"products", "order_items"})
    })

    t.Run("MonthlyRevenue", func(t *testing.T) {
        // Validate CTE with window functions
        gosqlxtesting.RequireValidSQL(t, queries.MonthlyRevenue)

        // Verify base table (CTEs are also extracted)
        tables := []string{"orders"}
        // Note: monthly_sales CTE may also be extracted
        gosqlxtesting.AssertTables(t, queries.MonthlyRevenue, tables)
    })
}
```

## Testing SQL Migration Scripts

```go
package migrations

import (
    "testing"
    gosqlxtesting "github.com/ajitpratap0/GoSQLX/pkg/gosqlx/testing"
)

func TestMigration_001_CreateUsersTable(t *testing.T) {
    createTableSQL := `
        CREATE TABLE users (
            id INT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            active BOOLEAN DEFAULT true,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `

    // Validate migration SQL is correct
    gosqlxtesting.RequireValidSQL(t, createTableSQL)

    // Verify it's a CREATE statement
    gosqlxtesting.AssertParsesTo(t, createTableSQL, &ast.CreateTableStatement{})
}

func TestMigration_002_AddIndexes(t *testing.T) {
    indexSQL := "CREATE INDEX idx_users_email ON users (email)"

    gosqlxtesting.RequireValidSQL(t, indexSQL)
    gosqlxtesting.AssertParsesTo(t, indexSQL, &ast.CreateIndexStatement{})
}
```

## Testing Dynamic Query Builders

```go
package querybuilder

import (
    "testing"
    "fmt"
    "strings"
    gosqlxtesting "github.com/ajitpratap0/GoSQLX/pkg/gosqlx/testing"
)

// QueryBuilder builds dynamic SQL queries
type QueryBuilder struct {
    table   string
    columns []string
    where   map[string]interface{}
}

func NewQueryBuilder(table string) *QueryBuilder {
    return &QueryBuilder{
        table:   table,
        columns: []string{"*"},
        where:   make(map[string]interface{}),
    }
}

func (qb *QueryBuilder) Select(cols ...string) *QueryBuilder {
    qb.columns = cols
    return qb
}

func (qb *QueryBuilder) Where(col string, val interface{}) *QueryBuilder {
    qb.where[col] = val
    return qb
}

func (qb *QueryBuilder) Build() string {
    query := fmt.Sprintf("SELECT %s FROM %s",
        strings.Join(qb.columns, ", "), qb.table)

    if len(qb.where) > 0 {
        conditions := make([]string, 0, len(qb.where))
        for col := range qb.where {
            conditions = append(conditions, fmt.Sprintf("%s = ?", col))
        }
        query += " WHERE " + strings.Join(conditions, " AND ")
    }

    return query
}

func TestQueryBuilder(t *testing.T) {
    t.Run("SimpleSelect", func(t *testing.T) {
        query := NewQueryBuilder("users").Build()

        gosqlxtesting.RequireValidSQL(t, query)
        gosqlxtesting.AssertTables(t, query, []string{"users"})
    })

    t.Run("SelectWithColumns", func(t *testing.T) {
        query := NewQueryBuilder("users").
            Select("id", "name", "email").
            Build()

        gosqlxtesting.RequireValidSQL(t, query)
        gosqlxtesting.AssertTables(t, query, []string{"users"})
        gosqlxtesting.AssertColumns(t, query, []string{"id", "name", "email"})
    })

    t.Run("SelectWithWhere", func(t *testing.T) {
        query := NewQueryBuilder("users").
            Select("id", "name").
            Where("active", true).
            Where("role", "admin").
            Build()

        gosqlxtesting.RequireValidSQL(t, query)
        gosqlxtesting.AssertTables(t, query, []string{"users"})
    })
}
```

## Table-Driven Tests for Multiple Dialects

```go
func TestSQLDialects(t *testing.T) {
    tests := []struct {
        name    string
        dialect string
        query   string
        valid   bool
    }{
        {
            name:    "PostgreSQL window function",
            dialect: "postgresql",
            query:   "SELECT id, ROW_NUMBER() OVER (ORDER BY created_at) FROM users",
            valid:   true,
        },
        {
            name:    "MySQL limit syntax",
            dialect: "mysql",
            query:   "SELECT * FROM users LIMIT 10 OFFSET 20",
            valid:   true,
        },
        {
            name:    "SQLite pragma",
            dialect: "sqlite",
            query:   "PRAGMA table_info(users)",
            valid:   false, // Not supported in current parser
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            if tt.valid {
                gosqlxtesting.AssertValidSQL(t, tt.query)
            } else {
                gosqlxtesting.AssertInvalidSQL(t, tt.query)
            }
        })
    }
}
```

## Best Practices

### 1. Use Require for Critical Checks

```go
// Use Require* to stop test immediately if SQL is invalid
gosqlxtesting.RequireValidSQL(t, criticalQuery)

// Continue with other assertions only if SQL is valid
gosqlxtesting.AssertTables(t, criticalQuery, expectedTables)
```

### 2. Test Error Messages

```go
// Test that your application generates appropriate errors
gosqlxtesting.AssertErrorContains(t, malformedSQL, "expected FROM")
```

### 3. Validate All Repository Queries

```go
// Test every SQL query in your repositories
func TestRepository_AllQueries(t *testing.T) {
    repo := NewRepository()

    queries := map[string]string{
        "select": repo.SelectQuery,
        "insert": repo.InsertQuery,
        "update": repo.UpdateQuery,
        "delete": repo.DeleteQuery,
    }

    for name, query := range queries {
        t.Run(name, func(t *testing.T) {
            gosqlxtesting.RequireValidSQL(t, query)
        })
    }
}
```

### 4. Test Dynamic SQL Builders

```go
// Test that your query builders generate valid SQL
func TestQueryBuilder_GeneratesValidSQL(t *testing.T) {
    builder := NewQueryBuilder()

    // Test various builder configurations
    variations := []QueryBuilder{
        builder.Select("*").From("users"),
        builder.Select("id", "name").From("users").Where("active", true),
        builder.Select("COUNT(*)").From("orders").GroupBy("status"),
    }

    for i, qb := range variations {
        t.Run(fmt.Sprintf("variation_%d", i), func(t *testing.T) {
            sql := qb.Build()
            gosqlxtesting.RequireValidSQL(t, sql)
        })
    }
}
```

## Common Patterns

### Pattern 1: Repository Testing

```go
func TestRepository(t *testing.T) {
    repo := NewUserRepository()

    // Test each query method
    t.Run("GetAll", func(t *testing.T) {
        query := repo.GetAllQuery()
        gosqlxtesting.RequireValidSQL(t, query)
        gosqlxtesting.AssertTables(t, query, []string{"users"})
    })
}
```

### Pattern 2: Migration Validation

```go
func TestMigrations(t *testing.T) {
    migrations := loadMigrationFiles()

    for _, migration := range migrations {
        t.Run(migration.Name, func(t *testing.T) {
            gosqlxtesting.RequireValidSQL(t, migration.SQL)
        })
    }
}
```

### Pattern 3: Query Builder Validation

```go
func TestBuilder(t *testing.T) {
    builder := NewSQLBuilder()
    sql := builder.Select("*").From("users").Where("active = true").Build()

    gosqlxtesting.RequireValidSQL(t, sql)
    gosqlxtesting.AssertTables(t, sql, []string{"users"})
}
```

## Troubleshooting

### Issue: AssertTables includes unexpected synthetic tables

**Solution**: The helper automatically filters tables with `(`, `_with_`, or starting with `_`. If you see unexpected tables, check if they match this pattern.

### Issue: AssertColumns doesn't extract columns from complex expressions

**Solution**: The column extractor focuses on simple identifiers. For complex expressions, use `RequireParse` and custom assertions.

### Issue: Test reports error at wrong line

**Solution**: Make sure all helper functions call `t.Helper()` - this package does this automatically.

## Summary

The GoSQLX testing helpers make it easy to:
- ✅ Validate SQL syntax in your test suite
- ✅ Verify table and column references
- ✅ Test statement types
- ✅ Ensure query builders generate valid SQL
- ✅ Validate database migrations
- ✅ Test complex SQL with CTEs and window functions

For more examples, see `demo_usage_test.go` and `example_test.go` in this package.
