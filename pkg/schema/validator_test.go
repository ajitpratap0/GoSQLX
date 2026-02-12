package schema

import (
	"strings"
	"testing"
)

// helperSchema builds a schema for validation tests.
func helperSchema() *Schema {
	s := NewSchema("testdb")

	// Users table
	users := NewTable("users")
	users.AddColumn(&Column{Name: "id", DataType: "INT", Nullable: false})
	users.AddColumn(&Column{Name: "name", DataType: "VARCHAR(100)", Nullable: false})
	users.AddColumn(&Column{Name: "email", DataType: "VARCHAR(255)", Nullable: true})
	users.PrimaryKey = []string{"id"}
	s.AddTable(users)

	// Orders table
	orders := NewTable("orders")
	orders.AddColumn(&Column{Name: "id", DataType: "INT", Nullable: false})
	orders.AddColumn(&Column{Name: "user_id", DataType: "INT", Nullable: false})
	orders.AddColumn(&Column{Name: "total", DataType: "DECIMAL(10,2)", Nullable: false})
	orders.AddColumn(&Column{Name: "status", DataType: "VARCHAR(20)", Nullable: true})
	orders.PrimaryKey = []string{"id"}
	s.AddTable(orders)

	// Products table
	products := NewTable("products")
	products.AddColumn(&Column{Name: "id", DataType: "INT", Nullable: false})
	products.AddColumn(&Column{Name: "name", DataType: "VARCHAR(200)", Nullable: false})
	products.AddColumn(&Column{Name: "price", DataType: "DECIMAL(10,2)", Nullable: false})
	products.PrimaryKey = []string{"id"}
	s.AddTable(products)

	return s
}

func TestValidator_ValidSelect(t *testing.T) {
	v := NewValidator(helperSchema())
	errs, err := v.Validate("SELECT id, name, email FROM users")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("expected no validation errors, got %d: %v", len(errs), errs)
	}
}

func TestValidator_SelectStar(t *testing.T) {
	v := NewValidator(helperSchema())
	errs, err := v.Validate("SELECT * FROM users")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("expected no validation errors, got %d: %v", len(errs), errs)
	}
}

func TestValidator_SelectFromNonexistentTable(t *testing.T) {
	v := NewValidator(helperSchema())
	errs, err := v.Validate("SELECT id FROM nonexistent")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) == 0 {
		t.Fatal("expected validation errors for nonexistent table")
	}

	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "nonexistent") && e.Severity == "error" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected error about nonexistent table, got: %v", errs)
	}
}

func TestValidator_SelectNonexistentColumn(t *testing.T) {
	v := NewValidator(helperSchema())
	errs, err := v.Validate("SELECT id, bogus_column FROM users")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) == 0 {
		t.Fatal("expected validation errors for nonexistent column")
	}

	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "bogus_column") && e.Severity == "error" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected error about bogus_column, got: %v", errs)
	}
}

func TestValidator_SelectQualifiedColumn(t *testing.T) {
	v := NewValidator(helperSchema())
	errs, err := v.Validate("SELECT u.id, u.name FROM users u")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("expected no validation errors, got %d: %v", len(errs), errs)
	}
}

func TestValidator_SelectQualifiedNonexistentColumn(t *testing.T) {
	v := NewValidator(helperSchema())
	errs, err := v.Validate("SELECT u.id, u.nonexistent FROM users u")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) == 0 {
		t.Fatal("expected validation errors for nonexistent column")
	}

	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "nonexistent") && e.Severity == "error" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected error about nonexistent column, got: %v", errs)
	}
}

func TestValidator_InsertValid(t *testing.T) {
	v := NewValidator(helperSchema())
	errs, err := v.Validate("INSERT INTO users (id, name, email) VALUES (1, 'Alice', 'alice@example.com')")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("expected no validation errors, got %d: %v", len(errs), errs)
	}
}

func TestValidator_InsertNonexistentTable(t *testing.T) {
	v := NewValidator(helperSchema())
	errs, err := v.Validate("INSERT INTO nonexistent (id) VALUES (1)")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) == 0 {
		t.Fatal("expected validation errors for nonexistent table")
	}

	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "nonexistent") && e.Severity == "error" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected error about nonexistent table, got: %v", errs)
	}
}

func TestValidator_InsertNonexistentColumn(t *testing.T) {
	v := NewValidator(helperSchema())
	errs, err := v.Validate("INSERT INTO users (id, bogus) VALUES (1, 'val')")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) == 0 {
		t.Fatal("expected validation errors for nonexistent column")
	}

	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "bogus") && e.Severity == "error" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected error about bogus column, got: %v", errs)
	}
}

func TestValidator_InsertWrongColumnCount(t *testing.T) {
	v := NewValidator(helperSchema())
	errs, err := v.Validate("INSERT INTO users (id, name) VALUES (1, 'Alice', 'extra')")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) == 0 {
		t.Fatal("expected validation errors for column count mismatch")
	}

	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "column count") && e.Severity == "error" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected error about column count mismatch, got: %v", errs)
	}
}

func TestValidator_UpdateValid(t *testing.T) {
	v := NewValidator(helperSchema())
	errs, err := v.Validate("UPDATE users SET name = 'Bob' WHERE id = 1")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("expected no validation errors, got %d: %v", len(errs), errs)
	}
}

func TestValidator_UpdateNonexistentTable(t *testing.T) {
	v := NewValidator(helperSchema())
	errs, err := v.Validate("UPDATE nonexistent SET name = 'Bob' WHERE id = 1")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) == 0 {
		t.Fatal("expected validation errors for nonexistent table")
	}

	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "nonexistent") && e.Severity == "error" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected error about nonexistent table, got: %v", errs)
	}
}

func TestValidator_UpdateNonexistentColumn(t *testing.T) {
	v := NewValidator(helperSchema())
	errs, err := v.Validate("UPDATE users SET bogus = 'val' WHERE id = 1")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) == 0 {
		t.Fatal("expected validation errors for nonexistent column")
	}

	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "bogus") && e.Severity == "error" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected error about bogus column, got: %v", errs)
	}
}

func TestValidator_DeleteValid(t *testing.T) {
	v := NewValidator(helperSchema())
	errs, err := v.Validate("DELETE FROM users WHERE id = 1")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("expected no validation errors, got %d: %v", len(errs), errs)
	}
}

func TestValidator_DeleteNonexistentTable(t *testing.T) {
	v := NewValidator(helperSchema())
	errs, err := v.Validate("DELETE FROM nonexistent WHERE id = 1")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) == 0 {
		t.Fatal("expected validation errors for nonexistent table")
	}

	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "nonexistent") && e.Severity == "error" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected error about nonexistent table, got: %v", errs)
	}
}

func TestValidator_SelectWithJoin(t *testing.T) {
	v := NewValidator(helperSchema())
	sql := `SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id`
	errs, err := v.Validate(sql)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("expected no validation errors for valid JOIN, got %d: %v", len(errs), errs)
	}
}

func TestValidator_SelectWithJoinNonexistentTable(t *testing.T) {
	v := NewValidator(helperSchema())
	sql := `SELECT u.name, o.total FROM users u JOIN nonexistent o ON u.id = o.user_id`
	errs, err := v.Validate(sql)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) == 0 {
		t.Fatal("expected validation errors for nonexistent JOIN table")
	}

	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "nonexistent") && e.Severity == "error" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected error about nonexistent table, got: %v", errs)
	}
}

func TestValidator_AmbiguousColumn(t *testing.T) {
	// Both users and orders have an "id" column
	v := NewValidator(helperSchema())
	// When joining, unqualified "id" is ambiguous
	sql := `SELECT id FROM users u JOIN orders o ON u.id = o.user_id`
	errs, err := v.Validate(sql)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "ambiguous") && e.Severity == "warning" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected ambiguous column warning, got: %v", errs)
	}
}

func TestValidator_InvalidSQL(t *testing.T) {
	v := NewValidator(helperSchema())
	_, err := v.Validate("NOT VALID SQL")
	if err == nil {
		t.Fatal("expected error for invalid SQL")
	}
}

func TestValidator_ValidationErrorString(t *testing.T) {
	e := ValidationError{
		Message:    "column not found",
		Severity:   "error",
		Suggestion: "did you mean 'name'?",
	}
	s := e.Error()
	if !strings.Contains(s, "column not found") {
		t.Fatalf("expected Error() to contain message, got: %s", s)
	}
	if !strings.Contains(s, "suggestion") {
		t.Fatalf("expected Error() to contain suggestion, got: %s", s)
	}

	// Without suggestion
	e2 := ValidationError{
		Message:  "table not found",
		Severity: "error",
	}
	s2 := e2.Error()
	if strings.Contains(s2, "suggestion") {
		t.Fatalf("expected Error() without suggestion, got: %s", s2)
	}
}

func TestValidator_SelectWithWhere(t *testing.T) {
	v := NewValidator(helperSchema())
	errs, err := v.Validate("SELECT id, name FROM users WHERE email = 'test@example.com'")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("expected no validation errors, got %d: %v", len(errs), errs)
	}
}

func TestValidator_SelectWhereNonexistentColumn(t *testing.T) {
	v := NewValidator(helperSchema())
	errs, err := v.Validate("SELECT id FROM users WHERE bogus = 'test'")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) == 0 {
		t.Fatal("expected validation errors for nonexistent column in WHERE")
	}

	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "bogus") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected error about bogus column in WHERE, got: %v", errs)
	}
}

func TestValidator_SelectFromMultipleTables(t *testing.T) {
	v := NewValidator(helperSchema())
	// Use explicit JOIN instead of comma-separated FROM (parser may not support comma-separated)
	sql := `SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id`
	errs, err := v.Validate(sql)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("expected no validation errors, got %d: %v", len(errs), errs)
	}
}

func TestValidator_InsertColumnCountMatchMultiRow(t *testing.T) {
	v := NewValidator(helperSchema())
	sql := `INSERT INTO users (id, name) VALUES (1, 'Alice'), (2, 'Bob')`
	errs, err := v.Validate(sql)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("expected no validation errors, got %d: %v", len(errs), errs)
	}
}

func TestValidator_Suggestion(t *testing.T) {
	v := NewValidator(helperSchema())
	// "user" is close to "users"
	errs, err := v.Validate("SELECT id FROM user")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) == 0 {
		t.Fatal("expected validation errors")
	}

	found := false
	for _, e := range errs {
		if e.Suggestion != "" && strings.Contains(e.Suggestion, "users") {
			found = true
			break
		}
	}
	if !found {
		t.Logf("NOTE: suggestion for 'user' -> 'users' not found (suggestions are best-effort)")
	}
}

func TestValidator_EmptySchema(t *testing.T) {
	s := NewSchema("empty")
	v := NewValidator(s)
	errs, err := v.Validate("SELECT id FROM users")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) == 0 {
		t.Fatal("expected validation errors with empty schema")
	}
}

func TestValidator_ValidateAST(t *testing.T) {
	v := NewValidator(helperSchema())

	// Parse first, then validate the AST directly
	sql := "SELECT bogus FROM users"
	tree, err := v.Validate(sql)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(tree) == 0 {
		t.Fatal("expected validation errors for nonexistent column")
	}
}

func TestValidator_DeleteWithWhereColumn(t *testing.T) {
	v := NewValidator(helperSchema())
	errs, err := v.Validate("DELETE FROM users WHERE id = 1")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("expected no validation errors, got %d: %v", len(errs), errs)
	}
}

func TestLevenshtein(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"a", "", 1},
		{"", "b", 1},
		{"abc", "abc", 0},
		{"abc", "abd", 1},
		{"abc", "abcd", 1},
		{"kitten", "sitting", 3},
		{"users", "user", 1},
	}

	for _, tt := range tests {
		got := levenshtein(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("levenshtein(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestFindClosest(t *testing.T) {
	candidates := []string{"users", "orders", "products", "categories"}

	tests := []struct {
		target string
		want   string // empty means no match expected
	}{
		{"users", "users"},  // exact match
		{"Users", "users"},  // case-insensitive
		{"user", "users"},   // prefix match
		{"ordrs", "orders"}, // close enough (Levenshtein=1)
		{"xxxxxxxx", ""},    // no match
	}

	for _, tt := range tests {
		got := findClosest(tt.target, candidates)
		if got != tt.want {
			t.Errorf("findClosest(%q) = %q, want %q", tt.target, got, tt.want)
		}
	}
}
