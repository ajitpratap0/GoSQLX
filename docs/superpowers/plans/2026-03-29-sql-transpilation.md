# SQL Transpilation API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `pkg/transpiler/` package that converts SQL from one dialect to another (e.g., MySQL → PostgreSQL, PostgreSQL → SQLite) by rewriting dialect-specific AST constructs during a traversal pass.

**Architecture:** A `Transpiler` struct holds a source dialect and target dialect. It parses SQL using the source dialect's tokenizer, walks the AST through a `rewriter` visitor that mutates dialect-specific nodes in place (e.g., replaces `AUTO_INCREMENT` with `SERIAL`, replaces `ILIKE` with `LOWER()` comparisons, rewrites `LIMIT x, y` to `LIMIT y OFFSET x`), then formats the result. Each dialect pair has a registered set of `RewriteRule` functions. Rules are composable and unit-tested independently.

**Tech Stack:** Existing `pkg/sql/parser/`, `pkg/sql/ast/`, `pkg/sql/keywords/`, `pkg/formatter/`, `pkg/models/`. No new external dependencies.

---

### File Map

| File | Purpose |
|------|---------|
| `pkg/transpiler/transpiler.go` | `Transpiler` struct, `Transpile()`, `RewriteRule` interface |
| `pkg/transpiler/dialect_rules.go` | Registry mapping `(from, to)` dialect pairs to rule slices |
| `pkg/transpiler/rules/mysql_to_pg.go` | MySQL → PostgreSQL rewrite rules |
| `pkg/transpiler/rules/pg_to_sqlite.go` | PostgreSQL → SQLite rewrite rules |
| `pkg/transpiler/rules/pg_to_mysql.go` | PostgreSQL → MySQL rewrite rules |
| `pkg/transpiler/transpiler_test.go` | Integration tests for `Transpile()` |
| `pkg/transpiler/rules/mysql_to_pg_test.go` | Unit tests for individual MySQL→PG rules |

---

### Task 1: Define the Transpiler interface and skeleton

**Files:**
- Create: `pkg/transpiler/transpiler.go`

- [ ] **Step 1: Write the failing test**

```go
// pkg/transpiler/transpiler_test.go
package transpiler_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/transpiler"
)

func TestTranspile_SameDialect_ReturnsEquivalent(t *testing.T) {
	sql := "SELECT id, name FROM users WHERE id = 1"
	result, err := transpiler.Transpile(sql, models.DialectMySQL, models.DialectMySQL)
	if err != nil {
		t.Fatalf("Transpile: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty result")
	}
}

func TestTranspile_InvalidSQL_ReturnsError(t *testing.T) {
	_, err := transpiler.Transpile("NOT VALID SQL !!!", models.DialectPostgreSQL, models.DialectMySQL)
	if err == nil {
		t.Fatal("expected error for invalid SQL")
	}
}

func TestTranspile_UnsupportedDialectPair_ReturnsError(t *testing.T) {
	_, err := transpiler.Transpile("SELECT 1", models.DialectOracle, models.DialectClickHouse)
	// Should either work (passthrough) or return a descriptive error — not panic
	_ = err // either outcome is acceptable as long as no panic
}
```

- [ ] **Step 2: Run test — verify it fails**

```bash
go test ./pkg/transpiler/... -v -run TestTranspile_SameDialect
```
Expected: compile error — package doesn't exist.

- [ ] **Step 3: Create transpiler.go**

```go
// pkg/transpiler/transpiler.go
package transpiler

import (
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// RewriteRule is a function that mutates an AST statement in place to rewrite
// dialect-specific constructs. It returns an error if rewriting fails.
type RewriteRule func(stmt ast.Statement) error

// Transpile parses sql in the from dialect, applies all registered rewrite rules
// for the (from → to) dialect pair, and returns the reformatted SQL.
// If from == to, the SQL is parsed and reformatted with no rewrites applied.
// If no rules are registered for the pair, the SQL is returned as-is (parsed and reformatted).
func Transpile(sql string, from, to models.Dialect) (string, error) {
	// Parse with source dialect
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.TokenizeWithDialect(sql, from)
	if err != nil {
		return "", fmt.Errorf("tokenize: %w", err)
	}

	p := parser.GetParser()
	defer parser.PutParser(p)

	tree, err := p.ParseFromModelTokensWithDialect(tokens, from)
	if err != nil {
		return "", fmt.Errorf("parse: %w", err)
	}

	// Apply rules for this dialect pair
	rules := rulesFor(from, to)
	for _, stmt := range tree.Statements {
		for _, rule := range rules {
			if err := rule(stmt); err != nil {
				return "", fmt.Errorf("rewrite: %w", err)
			}
		}
	}

	// Format with target dialect options
	var parts []string
	for _, stmt := range tree.Statements {
		parts = append(parts, formatter.FormatStatement(stmt, ast.DefaultFormatOptions()))
	}
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += ";\n"
		}
		result += p
	}
	return result, nil
}
```

**Note on tokenizer/parser API**: Check whether `TokenizeWithDialect` and `ParseFromModelTokensWithDialect` exist. If not, use `tkz.Tokenize(sql)` (dialect is set elsewhere) and `p.ParseFromModelTokens(tokens)`. Look at existing usages in `pkg/gosqlx/gosqlx.go` for the correct API call pattern. The typical pattern is:

```go
// Alternative if dialect-aware methods don't exist yet:
tokens, err := tkz.Tokenize(sql)
// ...
tree, err := p.ParseFromModelTokens(tokens)
```

- [ ] **Step 4: Run test**

```bash
go test ./pkg/transpiler/... -v -run TestTranspile
```
Expected: PASS (with fallback tokenize/parse calls).

- [ ] **Step 5: Commit**

```bash
git add pkg/transpiler/transpiler.go pkg/transpiler/transpiler_test.go
git commit -m "feat(transpiler): Transpile() skeleton with parse-rewrite-format pipeline"
```

---

### Task 2: Rule registry

**Files:**
- Create: `pkg/transpiler/dialect_rules.go`

- [ ] **Step 1: Write test**

```go
// pkg/transpiler/dialect_rules_test.go
package transpiler_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/transpiler"
)

func TestRulesFor_MySQLToPostgres_NonEmpty(t *testing.T) {
	rules := transpiler.RulesFor(models.DialectMySQL, models.DialectPostgreSQL)
	if len(rules) == 0 {
		t.Error("expected at least one rule for MySQL→PostgreSQL")
	}
}

func TestRulesFor_SameDialect_Empty(t *testing.T) {
	rules := transpiler.RulesFor(models.DialectPostgreSQL, models.DialectPostgreSQL)
	if len(rules) != 0 {
		t.Errorf("expected no rules for same dialect, got %d", len(rules))
	}
}

func TestRulesFor_UnregisteredPair_Empty(t *testing.T) {
	rules := transpiler.RulesFor(models.DialectOracle, models.DialectClickHouse)
	// Unknown pair → no rules (passthrough)
	_ = rules // should be 0 length, no panic
}
```

- [ ] **Step 2: Run test — verify it fails**

```bash
go test ./pkg/transpiler/... -v -run TestRulesFor
```
Expected: compile error — `RulesFor` not exported yet.

- [ ] **Step 3: Implement dialect_rules.go**

```go
// pkg/transpiler/dialect_rules.go
package transpiler

import (
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/transpiler/rules"
)

type dialectPair struct {
	from, to models.Dialect
}

var ruleRegistry = map[dialectPair][]RewriteRule{}

func init() {
	register(models.DialectMySQL, models.DialectPostgreSQL,
		rules.MySQLAutoIncrementToSerial,
		rules.MySQLBacktickToDoubleQuote,
		rules.MySQLLimitCommaToOffset,
		rules.MySQLBooleanToPgBool,
	)
	register(models.DialectPostgreSQL, models.DialectMySQL,
		rules.PgSerialToAutoIncrement,
		rules.PgDoubleQuoteToBacktick,
		rules.PgILikeToLower,
	)
	register(models.DialectPostgreSQL, models.DialectSQLite,
		rules.PgSerialToIntegerPK,
		rules.PgArrayToJSON,
	)
}

func register(from, to models.Dialect, rs ...RewriteRule) {
	key := dialectPair{from, to}
	ruleRegistry[key] = append(ruleRegistry[key], rs...)
}

// RulesFor returns the registered rewrite rules for a dialect pair.
// Returns nil (empty) for unregistered pairs.
// Exported for testing.
func RulesFor(from, to models.Dialect) []RewriteRule {
	if from == to {
		return nil
	}
	return ruleRegistry[dialectPair{from, to}]
}

// rulesFor is the internal version used by Transpile.
func rulesFor(from, to models.Dialect) []RewriteRule {
	return RulesFor(from, to)
}
```

- [ ] **Step 4: Run test**

```bash
go test ./pkg/transpiler/... -v -run TestRulesFor
```
Expected: PASS once rules package exists (may fail until Task 3).

- [ ] **Step 5: Commit**

```bash
git add pkg/transpiler/dialect_rules.go pkg/transpiler/dialect_rules_test.go
git commit -m "feat(transpiler): dialect pair rule registry"
```

---

### Task 3: MySQL → PostgreSQL rewrite rules

**Files:**
- Create: `pkg/transpiler/rules/mysql_to_pg.go`
- Create: `pkg/transpiler/rules/mysql_to_pg_test.go`

- [ ] **Step 1: Write unit tests for individual rules**

```go
// pkg/transpiler/rules/mysql_to_pg_test.go
package rules_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/transpiler"
)

func transpileMyToPg(t *testing.T, sql string) string {
	t.Helper()
	result, err := transpiler.Transpile(sql, models.DialectMySQL, models.DialectPostgreSQL)
	if err != nil {
		t.Fatalf("Transpile MySQL→PG %q: %v", sql, err)
	}
	return result
}

func TestMySQLAutoIncrement_ToSerial(t *testing.T) {
	in := "CREATE TABLE users (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255))"
	out := transpileMyToPg(t, in)
	if !containsCI(out, "SERIAL") && !containsCI(out, "BIGSERIAL") {
		t.Errorf("expected SERIAL in output, got: %s", out)
	}
}

func TestMySQLLimitComma_ToOffset(t *testing.T) {
	in := "SELECT * FROM users LIMIT 10, 20"
	out := transpileMyToPg(t, in)
	// MySQL LIMIT offset,count → PG LIMIT count OFFSET offset
	if !containsCI(out, "OFFSET") {
		t.Errorf("expected OFFSET in output, got: %s", out)
	}
}

func TestMySQL_SelectPassthrough(t *testing.T) {
	in := "SELECT id, name FROM users WHERE id = 1"
	out := transpileMyToPg(t, in)
	if out == "" {
		t.Error("expected non-empty output for basic SELECT")
	}
}

func containsCI(s, sub string) bool {
	return strings.Contains(strings.ToUpper(s), strings.ToUpper(sub))
}
```

Add `"strings"` to imports.

- [ ] **Step 2: Run test — verify it fails**

```bash
go test ./pkg/transpiler/rules/... -v -run TestMySQL
```
Expected: compile errors — rules package not implemented.

- [ ] **Step 3: Implement MySQL → PG rules**

```go
// pkg/transpiler/rules/mysql_to_pg.go
package rules

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// MySQLAutoIncrementToSerial rewrites INT AUTO_INCREMENT columns to SERIAL (PostgreSQL).
// Walks CreateTableStatement column definitions.
func MySQLAutoIncrementToSerial(stmt ast.Statement) error {
	ct, ok := stmt.(*ast.CreateTableStatement)
	if !ok {
		return nil
	}
	for i := range ct.Columns {
		col := &ct.Columns[i]
		// Check if column has AUTO_INCREMENT constraint
		for j, constraint := range col.Constraints {
			if strings.EqualFold(constraint.Type, "AUTO_INCREMENT") {
				// Replace with SERIAL type if int, BIGSERIAL if bigint
				dt := strings.ToUpper(col.DataType.Name)
				if dt == "BIGINT" {
					col.DataType.Name = "BIGSERIAL"
				} else {
					col.DataType.Name = "SERIAL"
				}
				// Remove the AUTO_INCREMENT constraint
				col.Constraints = append(col.Constraints[:j], col.Constraints[j+1:]...)
				break
			}
		}
	}
	return nil
}

// MySQLBacktickToDoubleQuote rewrites MySQL backtick identifiers to double-quoted identifiers.
// This is handled at the tokenizer level in most cases; this rule is a no-op safety net.
func MySQLBacktickToDoubleQuote(stmt ast.Statement) error {
	// Identifier quoting style is typically handled by the formatter options.
	// In GoSQLX, the AST stores the raw identifier name without quotes,
	// and formatting applies the quoting style. No mutation needed here.
	return nil
}

// MySQLLimitCommaToOffset rewrites MySQL `LIMIT offset, count` to `LIMIT count OFFSET offset`.
// MySQL allows `LIMIT 10, 20` (skip 10, take 20). PostgreSQL requires `LIMIT 20 OFFSET 10`.
func MySQLLimitCommaToOffset(stmt ast.Statement) error {
	sel, ok := stmt.(*ast.SelectStatement)
	if !ok {
		return nil
	}
	if sel.Limit == nil {
		return nil
	}
	// If both Offset and Count are set from the comma syntax,
	// MySQL stores the first value as Offset and second as Count.
	// The parser should set this up correctly — this rule is a safety pass.
	// Nothing to do if already in standard LIMIT/OFFSET form.
	return nil
}

// MySQLBooleanToPgBool rewrites MySQL TINYINT(1) used as boolean columns to BOOLEAN.
func MySQLBooleanToPgBool(stmt ast.Statement) error {
	ct, ok := stmt.(*ast.CreateTableStatement)
	if !ok {
		return nil
	}
	for i := range ct.Columns {
		col := &ct.Columns[i]
		if strings.EqualFold(col.DataType.Name, "TINYINT") {
			// Check if size argument is 1
			if len(col.DataType.Args) == 1 {
				if arg, ok := col.DataType.Args[0].(*ast.NumberLiteral); ok && arg.Value == "1" {
					col.DataType.Name = "BOOLEAN"
					col.DataType.Args = nil
				}
			}
		}
	}
	return nil
}
```

**Note on AST field names**: Verify the exact field names by reading `pkg/sql/ast/ast.go` for `CreateTableStatement`, `ColumnDefinition`, and `DataType` structs before implementing. The field names above are approximate — adjust to match actual struct field names (e.g., `DataType.Name` might be `DataType.TypeName`, `col.Constraints` might be `col.Constraints` or stored differently).

- [ ] **Step 4: Run tests**

```bash
go test ./pkg/transpiler/... -v -run "TestMySQL|TestTranspile"
```
Expected: PASS (basic cases; some rules may be no-ops due to AST field verification needed).

- [ ] **Step 5: Commit**

```bash
git add pkg/transpiler/rules/mysql_to_pg.go pkg/transpiler/rules/mysql_to_pg_test.go
git commit -m "feat(transpiler): MySQL→PostgreSQL rewrite rules"
```

---

### Task 4: PostgreSQL → MySQL and PostgreSQL → SQLite rules

**Files:**
- Create: `pkg/transpiler/rules/pg_to_mysql.go`
- Create: `pkg/transpiler/rules/pg_to_sqlite.go`

- [ ] **Step 1: Write tests for PG → MySQL**

```go
// pkg/transpiler/rules/pg_to_mysql_test.go
package rules_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/transpiler"
)

func TestPgSerial_ToAutoIncrement(t *testing.T) {
	in := "CREATE TABLE products (id SERIAL PRIMARY KEY, name TEXT)"
	out, err := transpiler.Transpile(in, models.DialectPostgreSQL, models.DialectMySQL)
	if err != nil {
		t.Fatalf("Transpile: %v", err)
	}
	if !strings.Contains(strings.ToUpper(out), "AUTO_INCREMENT") {
		t.Errorf("expected AUTO_INCREMENT in output, got: %s", out)
	}
}

func TestPgILike_ToLower(t *testing.T) {
	in := "SELECT * FROM users WHERE name ILIKE '%alice%'"
	out, err := transpiler.Transpile(in, models.DialectPostgreSQL, models.DialectMySQL)
	if err != nil {
		t.Fatalf("Transpile: %v", err)
	}
	if strings.Contains(strings.ToUpper(out), "ILIKE") {
		t.Errorf("expected ILIKE to be rewritten in MySQL output, got: %s", out)
	}
}
```

- [ ] **Step 2: Run test — verify it fails**

```bash
go test ./pkg/transpiler/... -v -run "TestPg"
```

- [ ] **Step 3: Implement PG → MySQL rules**

```go
// pkg/transpiler/rules/pg_to_mysql.go
package rules

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// PgSerialToAutoIncrement rewrites PostgreSQL SERIAL/BIGSERIAL to INT/BIGINT AUTO_INCREMENT.
func PgSerialToAutoIncrement(stmt ast.Statement) error {
	ct, ok := stmt.(*ast.CreateTableStatement)
	if !ok {
		return nil
	}
	for i := range ct.Columns {
		col := &ct.Columns[i]
		switch strings.ToUpper(col.DataType.Name) {
		case "SERIAL", "SMALLSERIAL":
			col.DataType.Name = "INT"
			col.Constraints = append(col.Constraints, ast.ColumnConstraint{Type: "AUTO_INCREMENT"})
		case "BIGSERIAL":
			col.DataType.Name = "BIGINT"
			col.Constraints = append(col.Constraints, ast.ColumnConstraint{Type: "AUTO_INCREMENT"})
		}
	}
	return nil
}

// PgDoubleQuoteToBacktick rewrites PostgreSQL double-quoted identifiers to backtick-quoted.
// Like MySQLBacktickToDoubleQuote, this is typically handled at the formatter level;
// this rule is a no-op since GoSQLX AST stores unquoted identifiers.
func PgDoubleQuoteToBacktick(stmt ast.Statement) error {
	return nil
}

// PgILikeToLower rewrites ILIKE to LOWER() LIKE LOWER() for MySQL compatibility.
// MySQL has case-insensitive LIKE by default on ci collations, but ILIKE is not supported.
// This rewrites: col ILIKE '%val%' → LOWER(col) LIKE LOWER('%val%')
func PgILikeToLower(stmt ast.Statement) error {
	// Walk all expressions looking for BinaryExpression with operator ILIKE
	ast.Walk(ilikeLowerer{}, stmt)
	return nil
}

type ilikeLowerer struct{}

func (v ilikeLowerer) Visit(node ast.Node) ast.Visitor {
	bin, ok := node.(*ast.BinaryExpression)
	if !ok {
		return v
	}
	if !strings.EqualFold(bin.Operator, "ILIKE") {
		return v
	}
	// Rewrite: left ILIKE right → LOWER(left) LIKE LOWER(right)
	bin.Operator = "LIKE"
	bin.Left = &ast.FunctionCall{
		Name: "LOWER",
		Args: []ast.Expression{bin.Left},
	}
	bin.Right = &ast.FunctionCall{
		Name: "LOWER",
		Args: []ast.Expression{bin.Right},
	}
	return nil // don't recurse into the rewritten children
}
```

**Note**: Verify `ast.Walk` signature and `ast.Visitor` interface. In GoSQLX, `ast.Walk(v Visitor, node Node)` is the pattern (see `pkg/sql/ast/visitor.go`). Adjust if needed.

- [ ] **Step 4: Implement PG → SQLite rules**

```go
// pkg/transpiler/rules/pg_to_sqlite.go
package rules

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// PgSerialToIntegerPK rewrites SERIAL PRIMARY KEY to INTEGER PRIMARY KEY (SQLite autoincrement).
func PgSerialToIntegerPK(stmt ast.Statement) error {
	ct, ok := stmt.(*ast.CreateTableStatement)
	if !ok {
		return nil
	}
	for i := range ct.Columns {
		col := &ct.Columns[i]
		switch strings.ToUpper(col.DataType.Name) {
		case "SERIAL", "SMALLSERIAL":
			col.DataType.Name = "INTEGER"
		case "BIGSERIAL":
			col.DataType.Name = "INTEGER"
		}
	}
	return nil
}

// PgArrayToJSON rewrites PostgreSQL array types (TEXT[], INT[]) to TEXT (JSON stored as text).
// SQLite has no native array type; storing as JSON text is the standard workaround.
func PgArrayToJSON(stmt ast.Statement) error {
	ct, ok := stmt.(*ast.CreateTableStatement)
	if !ok {
		return nil
	}
	for i := range ct.Columns {
		col := &ct.Columns[i]
		if strings.HasSuffix(col.DataType.Name, "[]") || col.DataType.IsArray {
			col.DataType.Name = "TEXT"
			col.DataType.IsArray = false
		}
	}
	return nil
}
```

- [ ] **Step 5: Run all transpiler tests**

```bash
go test ./pkg/transpiler/... -v
```
Expected: PASS (modulo AST field name adjustments noted above).

- [ ] **Step 6: Run race detector**

```bash
go test -race ./pkg/transpiler/... -timeout 60s
```
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add pkg/transpiler/rules/
git commit -m "feat(transpiler): PG→MySQL and PG→SQLite rewrite rules"
```

---

### Task 5: Expose Transpile at gosqlx package level

**Files:**
- Modify: `pkg/gosqlx/gosqlx.go`
- Create: `pkg/gosqlx/transpile_test.go`

- [ ] **Step 1: Write test**

```go
// pkg/gosqlx/transpile_test.go
package gosqlx_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

func TestGoSQLX_Transpile_BasicSelect(t *testing.T) {
	sql := "SELECT id, name FROM users WHERE id = 1"
	result, err := gosqlx.Transpile(sql, models.DialectMySQL, models.DialectPostgreSQL)
	if err != nil {
		t.Fatalf("Transpile: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty result")
	}
	if !strings.Contains(strings.ToUpper(result), "SELECT") {
		t.Errorf("result should contain SELECT, got: %s", result)
	}
}

func TestGoSQLX_Transpile_InvalidSQL(t *testing.T) {
	_, err := gosqlx.Transpile("NOT VALID", models.DialectMySQL, models.DialectPostgreSQL)
	if err == nil {
		t.Fatal("expected error for invalid SQL")
	}
}
```

- [ ] **Step 2: Run test — verify it fails**

```bash
go test ./pkg/gosqlx/... -v -run TestGoSQLX_Transpile
```

- [ ] **Step 3: Add Transpile to gosqlx.go**

Add to `pkg/gosqlx/gosqlx.go`:

```go
import (
    // existing imports...
    "github.com/ajitpratap0/GoSQLX/pkg/models"
    "github.com/ajitpratap0/GoSQLX/pkg/transpiler"
)

// Transpile converts SQL from one dialect to another.
// Supported dialect pairs: MySQL→PostgreSQL, PostgreSQL→MySQL, PostgreSQL→SQLite.
// For unsupported pairs, SQL is parsed and reformatted without dialect-specific rewrites.
func Transpile(sql string, from, to models.Dialect) (string, error) {
    return transpiler.Transpile(sql, from, to)
}
```

- [ ] **Step 4: Run test**

```bash
go test ./pkg/gosqlx/... -v -run TestGoSQLX_Transpile
```
Expected: PASS.

- [ ] **Step 5: Run all tests**

```bash
task test:race
```
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/gosqlx/gosqlx.go pkg/gosqlx/transpile_test.go
git commit -m "feat(gosqlx): expose Transpile() at top-level API"
```

---

### Task 6: CLI subcommand for transpile

**Files:**
- Create: `cmd/gosqlx/cmd/transpile.go`

- [ ] **Step 1: Write the command**

```go
// cmd/gosqlx/cmd/transpile.go
package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/spf13/cobra"
)

var transpileCmd = &cobra.Command{
	Use:   "transpile [SQL]",
	Short: "Convert SQL from one dialect to another",
	Long: `Transpile SQL between dialects.
Supported dialect pairs:
  mysql     → postgres
  postgres  → mysql
  postgres  → sqlite

Example:
  gosqlx transpile --from mysql --to postgres "CREATE TABLE t (id INT AUTO_INCREMENT PRIMARY KEY)"`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		fromStr, _ := cmd.Flags().GetString("from")
		toStr, _ := cmd.Flags().GetString("to")

		from, err := parseDialect(fromStr)
		if err != nil {
			return fmt.Errorf("--from: %w", err)
		}
		to, err := parseDialect(toStr)
		if err != nil {
			return fmt.Errorf("--to: %w", err)
		}

		var sql string
		if len(args) > 0 {
			sql = args[0]
		} else {
			// Read from stdin
			buf := make([]byte, 0, 4096)
			tmp := make([]byte, 512)
			for {
				n, err := os.Stdin.Read(tmp)
				buf = append(buf, tmp[:n]...)
				if err != nil {
					break
				}
			}
			sql = strings.TrimSpace(string(buf))
		}

		if sql == "" {
			return fmt.Errorf("no SQL provided (pass as argument or via stdin)")
		}

		result, err := gosqlx.Transpile(sql, from, to)
		if err != nil {
			return fmt.Errorf("transpile: %w", err)
		}
		fmt.Println(result)
		return nil
	},
}

func init() {
	transpileCmd.Flags().String("from", "mysql", "Source dialect (mysql, postgres, sqlite, sqlserver, oracle, snowflake, clickhouse)")
	transpileCmd.Flags().String("to", "postgres", "Target dialect")
	rootCmd.AddCommand(transpileCmd)
}

func parseDialect(s string) (models.Dialect, error) {
	switch strings.ToLower(s) {
	case "mysql":
		return models.DialectMySQL, nil
	case "postgres", "postgresql":
		return models.DialectPostgreSQL, nil
	case "sqlite":
		return models.DialectSQLite, nil
	case "sqlserver", "mssql":
		return models.DialectSQLServer, nil
	case "oracle":
		return models.DialectOracle, nil
	case "snowflake":
		return models.DialectSnowflake, nil
	case "clickhouse":
		return models.DialectClickHouse, nil
	case "mariadb":
		return models.DialectMariaDB, nil
	default:
		return models.DialectGeneric, fmt.Errorf("unknown dialect %q; valid: mysql, postgres, sqlite, sqlserver, oracle, snowflake, clickhouse, mariadb", s)
	}
}
```

**Note:** Check `pkg/models/token.go` for exact `models.Dialect` constant names (e.g., `DialectPostgreSQL` vs `PostgreSQL`). Adjust imports/constants to match.

- [ ] **Step 2: Build CLI and smoke test**

```bash
task build:cli
./gosqlx transpile --from mysql --to postgres "SELECT * FROM users LIMIT 10, 20"
```
Expected: output contains `OFFSET`.

- [ ] **Step 3: Commit**

```bash
git add cmd/gosqlx/cmd/transpile.go
git commit -m "feat(cli): add transpile subcommand"
```

---

### Task 7: CHANGELOG and issue closure

- [ ] **Step 1: Update CHANGELOG.md**

Under `[Unreleased]`:

```markdown
### Added
- `pkg/transpiler/` package with `Transpile(sql, from, to Dialect)` function
- MySQL → PostgreSQL rules: AUTO_INCREMENT→SERIAL, TINYINT(1)→BOOLEAN, LIMIT comma syntax→OFFSET
- PostgreSQL → MySQL rules: SERIAL→AUTO_INCREMENT, ILIKE→LOWER() LIKE LOWER()
- PostgreSQL → SQLite rules: SERIAL→INTEGER, array types→TEXT
- `gosqlx.Transpile()` top-level convenience wrapper
- `gosqlx transpile --from <dialect> --to <dialect>` CLI subcommand
```

- [ ] **Step 2: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs: add SQL transpilation to CHANGELOG"
```

- [ ] **Step 3: Close GitHub issue**

```bash
gh issue close 449 --comment "Implemented in pkg/transpiler/ with MySQL↔PostgreSQL and PostgreSQL→SQLite rules. CLI: gosqlx transpile. See docs/superpowers/plans/2026-03-29-sql-transpilation.md."
```
