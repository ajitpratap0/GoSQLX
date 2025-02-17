# GoSQLX Examples

This directory contains example tests demonstrating the features of the GoSQLX SQL tokenizer, particularly its Unicode support capabilities.

## Test Files

### `tokenizer_test.go`

This file contains two main test suites:

1. **TestUnicodeIdentifiers**
   - Tests basic Unicode identifier handling
   - Demonstrates support for:
     - Unicode table names (e.g., "café")
     - Unicode column names (e.g., "名前")
     - Unicode string literals (e.g., '🍕')
     - Mixed ASCII and Unicode identifiers

2. **TestComplexQueries**
   - Tests complex SQL queries with Unicode
   - Demonstrates:
     - JOINs with Unicode table names
     - Aggregations with Unicode columns
     - Subqueries with Unicode identifiers
     - Complex WHERE clauses with Unicode

## Running the Tests

To run the tests:

```bash
# Run all tests
go test ./...

# Run only examples tests
go test ./examples

# Run with verbose output
go test -v ./examples
```

## Example Queries

Here are some example queries that demonstrate the Unicode support:

```sql
-- Basic Unicode identifier
SELECT * FROM "café" WHERE price > 5

-- Multiple Unicode identifiers
SELECT name FROM "über_rides" WHERE "straße" LIKE '%main%'

-- Complex JOIN with Unicode
SELECT u."名前", o.order_id, p."説明"
FROM "ユーザー" u
JOIN orders o ON u.id = o.user_id
JOIN "製品" p ON o.product_id = p.id
WHERE u."年齢" > 20
ORDER BY o.order_date DESC

-- Aggregation with Unicode columns
SELECT 
    c."地域",
    COUNT(*) as total_orders,
    AVG(o."価格") as avg_price
FROM "顧客" c
JOIN "注文" o ON c.id = o.customer_id
GROUP BY c."地域"
HAVING AVG(o."価格") > 1000
```

## Features Demonstrated

1. **Unicode Identifiers**
   - Support for quoted identifiers containing Unicode characters
   - Proper handling of Unicode quotes (e.g., «, », ", ")
   - Mixed ASCII and Unicode identifiers in the same query

2. **String Literals**
   - Unicode string literals
   - Escaped quotes in strings
   - Multi-line strings

3. **Complex Query Support**
   - JOINs with Unicode table aliases
   - Subqueries with Unicode identifiers
   - Aggregations with Unicode column names
   - GROUP BY and HAVING clauses with Unicode
   - ORDER BY with Unicode columns
