package ast

import (
	"reflect"
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
	if s == "" {
		t.Error("should not be empty")
	}
}

func TestColumnConstraint_String(t *testing.T) {
	// With default
	cc := &ColumnConstraint{Type: "DEFAULT", Default: &LiteralValue{Value: "0"}}
	s := cc.String()
	if s == "" {
		t.Error("should not be empty")
	}

	// With references
	cc2 := &ColumnConstraint{
		Type: "REFERENCES",
		References: &ReferenceDefinition{Table: "users", Columns: []string{"id"}},
	}
	s2 := cc2.String()
	if s2 == "" {
		t.Error("should not be empty")
	}

	// With check
	cc3 := &ColumnConstraint{Type: "CHECK", Check: &Identifier{Name: "x > 0"}}
	s3 := cc3.String()
	if s3 == "" {
		t.Error("should not be empty")
	}

	// Auto increment
	cc4 := &ColumnConstraint{AutoIncrement: true}
	s4 := cc4.String()
	if s4 == "" {
		t.Error("should not be empty")
	}
}
