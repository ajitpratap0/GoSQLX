package ast

import (
	"fmt"
	"reflect"
	"strings"
)

// StructField represents a field in a struct type
type StructField struct {
	Name string
	Type string
	Tags map[string]string
}

// ParseStructTags parses struct field tags into a map
func ParseStructTags(tag string) map[string]string {
	tags := make(map[string]string)
	for _, t := range strings.Split(tag, " ") {
		if t == "" {
			continue
		}
		parts := strings.SplitN(t, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.Trim(parts[0], `"`)
		value := strings.Trim(parts[1], `"`)
		tags[key] = value
	}
	return tags
}

// GetStructFields returns the fields of a struct type
func GetStructFields(t reflect.Type) []StructField {
	fields := make([]StructField, 0)
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		field := StructField{
			Name: f.Name,
			Type: f.Type.String(),
			Tags: ParseStructTags(string(f.Tag)),
		}
		fields = append(fields, field)
	}
	return fields
}

// String returns a string representation of a ColumnDef
func (c *ColumnDef) String() string {
	var b strings.Builder
	b.WriteString(c.Name)
	b.WriteString(" ")
	b.WriteString(c.Type)
	for _, constraint := range c.Constraints {
		b.WriteString(" ")
		b.WriteString(constraint.String())
	}
	return b.String()
}

// String returns a string representation of a ReferenceDefinition
func (r *ReferenceDefinition) String() string {
	var b strings.Builder
	b.WriteString("REFERENCES ")
	b.WriteString(r.Table)
	if len(r.Columns) > 0 {
		b.WriteString(" (")
		b.WriteString(strings.Join(r.Columns, ", "))
		b.WriteString(")")
	}
	if r.OnDelete != "" {
		b.WriteString(" ON DELETE ")
		b.WriteString(r.OnDelete)
	}
	if r.OnUpdate != "" {
		b.WriteString(" ON UPDATE ")
		b.WriteString(r.OnUpdate)
	}
	if r.Match != "" {
		b.WriteString(" MATCH ")
		b.WriteString(r.Match)
	}
	return b.String()
}

// String returns a string representation of a ColumnConstraint
func (c *ColumnConstraint) String() string {
	var b strings.Builder
	b.WriteString(c.Type)
	if c.Default != nil {
		b.WriteString(" DEFAULT ")
		b.WriteString(fmt.Sprintf("%v", c.Default))
	}
	if c.References != nil {
		b.WriteString(" ")
		b.WriteString(c.References.String())
	}
	if c.Check != nil {
		b.WriteString(" CHECK (")
		b.WriteString(fmt.Sprintf("%v", c.Check))
		b.WriteString(")")
	}
	if c.AutoIncrement {
		b.WriteString(" AUTO_INCREMENT")
	}
	return b.String()
}
