# keywords package

SQL keyword tables and dialect identifiers.

Import path: `github.com/ajitpratap0/GoSQLX/pkg/sql/keywords` ([pkg.go.dev](https://pkg.go.dev/github.com/ajitpratap0/GoSQLX/pkg/sql/keywords))

Part of the [GoSQLX API reference](../API_REFERENCE.md).

## Core Types

### `Category` (Type)
```go
const (
    CategoryReserved Category = iota
    CategoryDML
    CategoryDDL
    CategoryDataType
    CategoryFunction
    CategoryOperator
    CategoryJoin
    CategoryWindow
    CategoryAggregate
)
```

## Functions

### `IsKeyword(word string) bool`
Check if string is a SQL keyword.

```go
keywords.IsKeyword("SELECT")  // true
keywords.IsKeyword("LATERAL") // true
```

### `GetCategory(word string) (Category, bool)`
Get keyword category.

```go
cat, ok := keywords.GetCategory("SELECT")
// Returns: CategoryDML, true
```

### `IsDMLKeyword(word string) bool`
Check if DML keyword.

### `IsDDLKeyword(word string) bool`
Check if DDL keyword.

### `IsReserved(word string) bool`
Check if reserved keyword.

### `IsFunction(word string) bool`
Check if function name.

### `IsAggregate(word string) bool`
Check if aggregate function.

### `IsWindowFunction(word string) bool`
Check if window function.

### `IsDataType(word string) bool`
Check if data type.

### `GetAllKeywords() []string`
Get all keywords.

### `GetKeywordsByCategory(cat Category) []string`
Get keywords by category.

## Dialect-Specific Functions

### `IsPostgreSQLKeyword(word string) bool`
### `IsMySQLKeyword(word string) bool`
### `IsSQLServerKeyword(word string) bool`
### `IsOracleKeyword(word string) bool`
### `IsSQLiteKeyword(word string) bool`

### `GetSuggestions(prefix string, maxResults int) []string`
Get keyword suggestions for autocomplete.

Suggestions are served from an LRU cache. See [benchmarks](/benchmarks/) for measured performance.

```go
suggestions := keywords.GetSuggestions("SEL", 5)
// Returns: ["SELECT"]
```
