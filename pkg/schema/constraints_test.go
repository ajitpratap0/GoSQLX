package schema

import (
	"strings"
	"testing"
)

// constraintSchema builds a schema with constraints for testing.
func constraintSchema() *Schema {
	s := NewSchema("testdb")

	users := NewTable("users")
	users.AddColumn(&Column{Name: "id", DataType: "INT", Nullable: false})
	users.AddColumn(&Column{Name: "name", DataType: "VARCHAR(100)", Nullable: false})
	users.AddColumn(&Column{Name: "email", DataType: "VARCHAR(255)", Nullable: true})
	users.AddColumn(&Column{Name: "age", DataType: "INT", Nullable: true})
	users.PrimaryKey = []string{"id"}
	s.AddTable(users)

	orders := NewTable("orders")
	orders.AddColumn(&Column{Name: "id", DataType: "INT", Nullable: false})
	orders.AddColumn(&Column{Name: "user_id", DataType: "INT", Nullable: false,
		References: &ForeignKeyRef{Table: "users", Column: "id"}})
	orders.AddColumn(&Column{Name: "total", DataType: "DECIMAL(10,2)", Nullable: false})
	orders.AddColumn(&Column{Name: "status", DataType: "VARCHAR(20)", Nullable: true})
	orders.PrimaryKey = []string{"id"}
	orders.ForeignKeys = []ForeignKey{
		{Name: "fk_user", Columns: []string{"user_id"}, RefTable: "users", RefColumns: []string{"id"}},
	}
	s.AddTable(orders)

	return s
}

func TestValidateInsertNotNull(t *testing.T) {
	v := NewValidator(constraintSchema())

	// INSERT NULL into NOT NULL column
	errs, err := v.Validate("INSERT INTO users (id, name) VALUES (1, NULL)")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "NOT NULL") && strings.Contains(e.Message, "name") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected NOT NULL violation for 'name', got errors: %v", errs)
	}
}

func TestValidateInsertNotNull_NullableOK(t *testing.T) {
	v := NewValidator(constraintSchema())

	// INSERT NULL into nullable column should be fine
	errs, err := v.Validate("INSERT INTO users (id, name, email) VALUES (1, 'Alice', NULL)")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	for _, e := range errs {
		if strings.Contains(e.Message, "NOT NULL") && strings.Contains(e.Message, "email") {
			t.Errorf("should not report NOT NULL error for nullable 'email' column, got: %v", e)
		}
	}
}

func TestValidateForeignKeys_Valid(t *testing.T) {
	v := NewValidator(constraintSchema())
	errs := v.ValidateForeignKeys()

	for _, e := range errs {
		if strings.Contains(e.Message, "foreign key") {
			t.Errorf("expected no FK errors for valid schema, got: %v", e)
		}
	}
}

func TestValidateForeignKeys_InvalidRef(t *testing.T) {
	s := NewSchema("test")

	users := NewTable("users")
	users.AddColumn(&Column{Name: "id", DataType: "INT"})
	s.AddTable(users)

	orders := NewTable("orders")
	orders.AddColumn(&Column{Name: "id", DataType: "INT"})
	orders.AddColumn(&Column{Name: "user_id", DataType: "INT"})
	orders.ForeignKeys = []ForeignKey{
		{Name: "fk_bad", Columns: []string{"user_id"}, RefTable: "nonexistent", RefColumns: []string{"id"}},
	}
	s.AddTable(orders)

	v := NewValidator(s)
	errs := v.ValidateForeignKeys()

	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "non-existent table") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected FK error for non-existent referenced table, got: %v", errs)
	}
}

func TestValidateForeignKeys_InvalidColumn(t *testing.T) {
	s := NewSchema("test")

	users := NewTable("users")
	users.AddColumn(&Column{Name: "id", DataType: "INT"})
	s.AddTable(users)

	orders := NewTable("orders")
	orders.AddColumn(&Column{Name: "id", DataType: "INT"})
	orders.AddColumn(&Column{Name: "user_id", DataType: "INT"})
	orders.ForeignKeys = []ForeignKey{
		{Name: "fk_bad_col", Columns: []string{"user_id"}, RefTable: "users", RefColumns: []string{"nonexistent_col"}},
	}
	s.AddTable(orders)

	v := NewValidator(s)
	errs := v.ValidateForeignKeys()

	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "non-existent column") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected FK error for non-existent column, got: %v", errs)
	}
}

func TestValidateColumnRefFK(t *testing.T) {
	s := NewSchema("test")

	users := NewTable("users")
	users.AddColumn(&Column{Name: "id", DataType: "INT"})
	s.AddTable(users)

	orders := NewTable("orders")
	orders.AddColumn(&Column{Name: "user_id", DataType: "INT",
		References: &ForeignKeyRef{Table: "nonexistent", Column: "id"}})
	s.AddTable(orders)

	v := NewValidator(s)
	errs := v.ValidateForeignKeys()

	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "non-existent table") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected column-level FK error, got: %v", errs)
	}
}

func TestCategorizeType(t *testing.T) {
	tests := []struct {
		dataType string
		want     TypeCategory
	}{
		{"INT", TypeCategoryNumeric},
		{"VARCHAR(100)", TypeCategoryString},
		{"DECIMAL(10,2)", TypeCategoryNumeric},
		{"BOOLEAN", TypeCategoryBoolean},
		{"DATE", TypeCategoryDateTime},
		{"TIMESTAMP", TypeCategoryDateTime},
		{"TEXT", TypeCategoryString},
		{"BIGINT", TypeCategoryNumeric},
		{"UNKNOWN_TYPE", TypeCategoryUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.dataType, func(t *testing.T) {
			got := categorizeType(tt.dataType)
			if got != tt.want {
				t.Errorf("categorizeType(%q) = %d, want %d", tt.dataType, got, tt.want)
			}
		})
	}
}

func TestTypeCategoryName(t *testing.T) {
	if typeCategoryName(TypeCategoryNumeric) != "numeric" {
		t.Error("expected 'numeric'")
	}
	if typeCategoryName(TypeCategoryString) != "string" {
		t.Error("expected 'string'")
	}
	if typeCategoryName(TypeCategoryUnknown) != "unknown" {
		t.Error("expected 'unknown'")
	}
}

func TestMissingNotNullColumnWarning(t *testing.T) {
	v := NewValidator(constraintSchema())

	// INSERT that's missing the NOT NULL 'name' column (not PK, no DEFAULT)
	errs, err := v.Validate("INSERT INTO users (id) VALUES (1)")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "NOT NULL column") && strings.Contains(e.Message, "name") && e.Severity == "warning" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected warning about missing NOT NULL column 'name', got: %v", errs)
	}
}
