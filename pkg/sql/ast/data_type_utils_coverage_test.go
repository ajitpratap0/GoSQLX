package ast

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseStructTags(t *testing.T) {
	tests := []struct {
		tag  string
		want map[string]string
	}{
		{`json:"name" db:"col"`, map[string]string{"json": "name", "db": "col"}},
		{``, map[string]string{}},
		{`json:"value"`, map[string]string{"json": "value"}},
		{`badtag`, map[string]string{}},
	}
	for _, tt := range tests {
		got := ParseStructTags(tt.tag)
		if len(got) != len(tt.want) {
			t.Errorf("ParseStructTags(%q) = %v, want %v", tt.tag, got, tt.want)
		}
	}
}

func TestGetStructFields(t *testing.T) {
	type TestStruct struct {
		Name string `json:"name"`
		Age  int    `db:"age"`
	}
	fields := GetStructFields(reflect.TypeOf(TestStruct{}))
	if len(fields) != 2 {
		t.Fatalf("expected 2 fields, got %d", len(fields))
	}
	if fields[0].Name != "Name" {
		t.Errorf("first field name = %q", fields[0].Name)
	}
}

func TestColumnDef_String(t *testing.T) {
	cd := &ColumnDef{
		Name: "id",
		Type: "INT",
		Constraints: []ColumnConstraint{
			{Type: "NOT NULL"},
		},
	}
	s := cd.String()
	if s != "id INT NOT NULL" {
		t.Errorf("ColumnDef.String() = %q", s)
	}
}

func TestReferenceDefinition_String(t *testing.T) {
	r := &ReferenceDefinition{
		Table:    "orders",
		Columns:  []string{"id"},
		OnDelete: "CASCADE",
		OnUpdate: "SET NULL",
		Match:    "FULL",
	}
	s := r.String()
	for _, want := range []string{"orders", "id", "CASCADE", "SET NULL", "FULL"} {
		if !strings.Contains(s, want) {
			t.Errorf("ReferenceDefinition.String() missing %q, got: %s", want, s)
		}
	}
}

func TestColumnConstraint_String(t *testing.T) {
	// With default
	cc := &ColumnConstraint{Type: "DEFAULT", Default: &LiteralValue{Value: "0"}}
	s := cc.String()
	if !strings.Contains(s, "DEFAULT") || !strings.Contains(s, "0") {
		t.Errorf("ColumnConstraint DEFAULT should contain 'DEFAULT' and '0', got: %s", s)
	}

	// With references
	cc2 := &ColumnConstraint{
		Type:       "REFERENCES",
		References: &ReferenceDefinition{Table: "users", Columns: []string{"id"}},
	}
	s2 := cc2.String()
	if !strings.Contains(s2, "REFERENCES") || !strings.Contains(s2, "users") {
		t.Errorf("ColumnConstraint REFERENCES should contain 'REFERENCES' and 'users', got: %s", s2)
	}

	// With check
	cc3 := &ColumnConstraint{Type: "CHECK", Check: &Identifier{Name: "x > 0"}}
	s3 := cc3.String()
	if !strings.Contains(s3, "CHECK") {
		t.Errorf("ColumnConstraint CHECK should contain 'CHECK', got: %s", s3)
	}

	// Auto increment
	cc4 := &ColumnConstraint{AutoIncrement: true}
	s4 := cc4.String()
	if !strings.Contains(s4, "AUTO_INCREMENT") && !strings.Contains(s4, "AUTOINCREMENT") && !strings.Contains(strings.ToUpper(s4), "AUTO") {
		t.Errorf("ColumnConstraint AutoIncrement should mention auto increment, got: %s", s4)
	}
}
