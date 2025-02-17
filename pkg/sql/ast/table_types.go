package ast

// Table represents a table definition
type Table struct {
	Name        string
	Columns     []*ColumnDef
	Constraints []*TableConstraint
	Options     map[string]string
}
