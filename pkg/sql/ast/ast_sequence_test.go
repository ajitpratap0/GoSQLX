package ast_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func TestCreateSequenceStatement_ToSQL(t *testing.T) {
	tests := []struct {
		name string
		stmt *ast.CreateSequenceStatement
		want string
	}{
		{
			name: "minimal",
			stmt: &ast.CreateSequenceStatement{
				Name: &ast.Identifier{Name: "seq_orders"},
			},
			want: "CREATE SEQUENCE seq_orders",
		},
		{
			name: "or replace",
			stmt: &ast.CreateSequenceStatement{
				Name:      &ast.Identifier{Name: "seq_orders"},
				OrReplace: true,
			},
			want: "CREATE OR REPLACE SEQUENCE seq_orders",
		},
		{
			name: "if not exists",
			stmt: &ast.CreateSequenceStatement{
				Name:        &ast.Identifier{Name: "seq_orders"},
				IfNotExists: true,
			},
			want: "CREATE SEQUENCE IF NOT EXISTS seq_orders",
		},
		{
			name: "with options",
			stmt: &ast.CreateSequenceStatement{
				Name: &ast.Identifier{Name: "s"},
				Options: ast.SequenceOptions{
					StartWith:   &ast.LiteralValue{Value: "1"},
					IncrementBy: &ast.LiteralValue{Value: "1"},
					MinValue:    &ast.LiteralValue{Value: "1"},
					MaxValue:    &ast.LiteralValue{Value: "9999"},
					Cache:       &ast.LiteralValue{Value: "100"},
					Cycle:       true,
				},
			},
			want: "CREATE SEQUENCE s START WITH 1 INCREMENT BY 1 MINVALUE 1 MAXVALUE 9999 CACHE 100 CYCLE",
		},
		{
			name: "nocycle",
			stmt: &ast.CreateSequenceStatement{
				Name:    &ast.Identifier{Name: "s"},
				Options: ast.SequenceOptions{NoCycle: true},
			},
			want: "CREATE SEQUENCE s NOCYCLE",
		},
		{
			name: "nocache",
			stmt: &ast.CreateSequenceStatement{
				Name:    &ast.Identifier{Name: "s"},
				Options: ast.SequenceOptions{NoCache: true},
			},
			want: "CREATE SEQUENCE s NOCACHE",
		},
		{
			name: "nil name does not panic",
			stmt: &ast.CreateSequenceStatement{},
			want: "CREATE SEQUENCE ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.stmt.ToSQL()
			if got != tt.want {
				t.Errorf("ToSQL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDropSequenceStatement_ToSQL(t *testing.T) {
	tests := []struct {
		name string
		stmt *ast.DropSequenceStatement
		want string
	}{
		{
			name: "basic",
			stmt: &ast.DropSequenceStatement{Name: &ast.Identifier{Name: "seq_orders"}},
			want: "DROP SEQUENCE seq_orders",
		},
		{
			name: "if exists",
			stmt: &ast.DropSequenceStatement{Name: &ast.Identifier{Name: "seq_orders"}, IfExists: true},
			want: "DROP SEQUENCE IF EXISTS seq_orders",
		},
		{
			name: "nil name does not panic",
			stmt: &ast.DropSequenceStatement{},
			want: "DROP SEQUENCE ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.stmt.ToSQL()
			if got != tt.want {
				t.Errorf("ToSQL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAlterSequenceStatement_ToSQL(t *testing.T) {
	tests := []struct {
		name string
		stmt *ast.AlterSequenceStatement
		want string
	}{
		{
			name: "restart bare",
			stmt: &ast.AlterSequenceStatement{
				Name:    &ast.Identifier{Name: "s"},
				Options: ast.SequenceOptions{Restart: true},
			},
			want: "ALTER SEQUENCE s RESTART",
		},
		{
			name: "restart with value",
			stmt: &ast.AlterSequenceStatement{
				Name: &ast.Identifier{Name: "s"},
				Options: ast.SequenceOptions{
					RestartWith: &ast.LiteralValue{Value: "1"},
				},
			},
			want: "ALTER SEQUENCE s RESTART WITH 1",
		},
		{
			name: "nil name does not panic",
			stmt: &ast.AlterSequenceStatement{},
			want: "ALTER SEQUENCE ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.stmt.ToSQL()
			if got != tt.want {
				t.Errorf("ToSQL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSequencePool_RoundTrip(t *testing.T) {
	s := ast.NewCreateSequenceStatement()
	if s == nil {
		t.Fatal("NewCreateSequenceStatement() returned nil")
	}
	s.Name = &ast.Identifier{Name: "test"}
	ast.ReleaseCreateSequenceStatement(s)

	s2 := ast.NewCreateSequenceStatement()
	if s2 == nil {
		t.Fatal("second NewCreateSequenceStatement() returned nil")
	}
	if s2.Name != nil {
		t.Error("expected Name to be nil after release (pool zero-reset)")
	}
	ast.ReleaseCreateSequenceStatement(s2)
}

func TestSelectStatement_ConnectBy_SQLOrder(t *testing.T) {
	limit := 10
	stmt := &ast.SelectStatement{
		Columns: []ast.Expression{&ast.Identifier{Name: "*"}},
		From: []ast.TableReference{
			{Name: "employees"},
		},
		StartWith: &ast.BinaryExpression{
			Left:     &ast.Identifier{Name: "parent_id"},
			Operator: "IS",
			Right:    &ast.Identifier{Name: "NULL"},
		},
		ConnectBy: &ast.ConnectByClause{
			NoCycle: true,
			Condition: &ast.BinaryExpression{
				Left:     &ast.UnaryExpression{Operator: ast.Prior, Expr: &ast.Identifier{Name: "id"}},
				Operator: "=",
				Right:    &ast.Identifier{Name: "parent_id"},
			},
		},
		OrderBy: []ast.OrderByExpression{
			{Expression: &ast.Identifier{Name: "id"}},
		},
		Limit: &limit,
	}
	got := stmt.SQL()
	startIdx := strings.Index(got, "START WITH")
	orderIdx := strings.Index(got, "ORDER BY")
	if startIdx == -1 {
		t.Fatal("SQL() missing START WITH")
	}
	if orderIdx == -1 {
		t.Fatal("SQL() missing ORDER BY")
	}
	if startIdx > orderIdx {
		t.Errorf("START WITH appears after ORDER BY in SQL():\n  %s", got)
	}
}

func TestPeriodDefinition_SQL(t *testing.T) {
	pd := &ast.PeriodDefinition{
		Name:     &ast.Identifier{Name: "app_time"},
		StartCol: &ast.Identifier{Name: "valid_from"},
		EndCol:   &ast.Identifier{Name: "valid_to"},
	}
	got := pd.SQL()
	want := "PERIOD FOR app_time (valid_from, valid_to)"
	if got != want {
		t.Errorf("PeriodDefinition.SQL() = %q, want %q", got, want)
	}
}

func TestPeriodDefinition_SQL_SystemTime(t *testing.T) {
	pd := &ast.PeriodDefinition{
		Name:     &ast.Identifier{Name: "SYSTEM_TIME"},
		StartCol: &ast.Identifier{Name: "row_start"},
		EndCol:   &ast.Identifier{Name: "row_end"},
	}
	got := pd.SQL()
	want := "PERIOD FOR SYSTEM_TIME (row_start, row_end)"
	if got != want {
		t.Errorf("PeriodDefinition.SQL() = %q, want %q", got, want)
	}
}
