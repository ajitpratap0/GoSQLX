package ast

import (
	"testing"
)

func TestSelectStatementSQL(t *testing.T) {
	tests := []struct {
		name string
		stmt *SelectStatement
		want string
	}{
		{
			name: "simple select",
			stmt: &SelectStatement{
				Columns: []Expression{&Identifier{Name: "*"}},
				From:    []TableReference{{Name: "users"}},
			},
			want: "SELECT * FROM users",
		},
		{
			name: "select with where",
			stmt: &SelectStatement{
				Columns: []Expression{&Identifier{Name: "id"}, &Identifier{Name: "name"}},
				From:    []TableReference{{Name: "users"}},
				Where: &BinaryExpression{
					Left:     &Identifier{Name: "active"},
					Operator: "=",
					Right:    &LiteralValue{Value: true, Type: "BOOLEAN"},
				},
			},
			want: "SELECT id, name FROM users WHERE active = TRUE",
		},
		{
			name: "select distinct",
			stmt: &SelectStatement{
				Distinct: true,
				Columns:  []Expression{&Identifier{Name: "status"}},
				From:     []TableReference{{Name: "orders"}},
			},
			want: "SELECT DISTINCT status FROM orders",
		},
		{
			name: "select with alias",
			stmt: &SelectStatement{
				Columns: []Expression{
					&AliasedExpression{
						Expr:  &FunctionCall{Name: "COUNT", Arguments: []Expression{&Identifier{Name: "*"}}},
						Alias: "total",
					},
				},
				From: []TableReference{{Name: "users"}},
			},
			want: "SELECT COUNT(*) AS total FROM users",
		},
		{
			name: "select with join",
			stmt: &SelectStatement{
				Columns: []Expression{&Identifier{Name: "u.name"}, &Identifier{Name: "o.total"}},
				From:    []TableReference{{Name: "users", Alias: "u"}},
				Joins: []JoinClause{
					{
						Type:  "LEFT",
						Right: TableReference{Name: "orders", Alias: "o"},
						Condition: &BinaryExpression{
							Left:     &Identifier{Name: "u.id"},
							Operator: "=",
							Right:    &Identifier{Name: "o.user_id"},
						},
					},
				},
			},
			want: "SELECT u.name, o.total FROM users u LEFT JOIN orders o ON u.id = o.user_id",
		},
		{
			name: "select with order by and limit",
			stmt: &SelectStatement{
				Columns: []Expression{&Identifier{Name: "*"}},
				From:    []TableReference{{Name: "products"}},
				OrderBy: []OrderByExpression{
					{Expression: &Identifier{Name: "price"}, Ascending: false},
				},
				Limit: intPtr(10),
			},
			want: "SELECT * FROM products ORDER BY price DESC LIMIT 10",
		},
		{
			name: "select with group by and having",
			stmt: &SelectStatement{
				Columns: []Expression{
					&Identifier{Name: "dept"},
					&AliasedExpression{
						Expr:  &FunctionCall{Name: "COUNT", Arguments: []Expression{&Identifier{Name: "*"}}},
						Alias: "cnt",
					},
				},
				From:    []TableReference{{Name: "employees"}},
				GroupBy: []Expression{&Identifier{Name: "dept"}},
				Having: &BinaryExpression{
					Left:     &FunctionCall{Name: "COUNT", Arguments: []Expression{&Identifier{Name: "*"}}},
					Operator: ">",
					Right:    &LiteralValue{Value: 5, Type: "INTEGER"},
				},
			},
			want: "SELECT dept, COUNT(*) AS cnt FROM employees GROUP BY dept HAVING COUNT(*) > 5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.stmt.SQL()
			if got != tt.want {
				t.Errorf("SQL() =\n  %s\nwant:\n  %s", got, tt.want)
			}
		})
	}
}

func TestInsertStatementSQL(t *testing.T) {
	tests := []struct {
		name string
		stmt *InsertStatement
		want string
	}{
		{
			name: "simple insert",
			stmt: &InsertStatement{
				TableName: "users",
				Columns:   []Expression{&Identifier{Name: "name"}, &Identifier{Name: "email"}},
				Values: [][]Expression{
					{&LiteralValue{Value: "Alice", Type: "STRING"}, &LiteralValue{Value: "alice@example.com", Type: "STRING"}},
				},
			},
			want: "INSERT INTO users (name, email) VALUES ('Alice', 'alice@example.com')",
		},
		{
			name: "multi-row insert",
			stmt: &InsertStatement{
				TableName: "users",
				Columns:   []Expression{&Identifier{Name: "name"}},
				Values: [][]Expression{
					{&LiteralValue{Value: "Alice", Type: "STRING"}},
					{&LiteralValue{Value: "Bob", Type: "STRING"}},
				},
			},
			want: "INSERT INTO users (name) VALUES ('Alice'), ('Bob')",
		},
		{
			name: "insert with on conflict",
			stmt: &InsertStatement{
				TableName: "users",
				Columns:   []Expression{&Identifier{Name: "email"}, &Identifier{Name: "name"}},
				Values: [][]Expression{
					{&LiteralValue{Value: "a@b.com", Type: "STRING"}, &LiteralValue{Value: "A", Type: "STRING"}},
				},
				OnConflict: &OnConflict{
					Target: []Expression{&Identifier{Name: "email"}},
					Action: OnConflictAction{
						DoUpdate: []UpdateExpression{
							{Column: &Identifier{Name: "name"}, Value: &Identifier{Name: "EXCLUDED.name"}},
						},
					},
				},
			},
			want: "INSERT INTO users (email, name) VALUES ('a@b.com', 'A') ON CONFLICT (email) DO UPDATE SET name = EXCLUDED.name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.stmt.SQL()
			if got != tt.want {
				t.Errorf("SQL() =\n  %s\nwant:\n  %s", got, tt.want)
			}
		})
	}
}

func TestUpdateStatementSQL(t *testing.T) {
	stmt := &UpdateStatement{
		TableName: "users",
		Updates: []UpdateExpression{
			{Column: &Identifier{Name: "name"}, Value: &LiteralValue{Value: "Bob", Type: "STRING"}},
		},
		Where: &BinaryExpression{
			Left:     &Identifier{Name: "id"},
			Operator: "=",
			Right:    &LiteralValue{Value: 1, Type: "INTEGER"},
		},
	}
	want := "UPDATE users SET name = 'Bob' WHERE id = 1"
	if got := stmt.SQL(); got != want {
		t.Errorf("SQL() = %s, want %s", got, want)
	}
}

func TestDeleteStatementSQL(t *testing.T) {
	stmt := &DeleteStatement{
		TableName: "users",
		Where: &BinaryExpression{
			Left:     &Identifier{Name: "id"},
			Operator: "=",
			Right:    &LiteralValue{Value: 1, Type: "INTEGER"},
		},
	}
	want := "DELETE FROM users WHERE id = 1"
	if got := stmt.SQL(); got != want {
		t.Errorf("SQL() = %s, want %s", got, want)
	}
}

func TestCreateTableStatementSQL(t *testing.T) {
	stmt := &CreateTableStatement{
		Name: "users",
		Columns: []ColumnDef{
			{Name: "id", Type: "INTEGER", Constraints: []ColumnConstraint{{Type: "PRIMARY KEY"}}},
			{Name: "name", Type: "VARCHAR(255)", Constraints: []ColumnConstraint{{Type: "NOT NULL"}}},
			{Name: "email", Type: "VARCHAR(255)", Constraints: []ColumnConstraint{{Type: "UNIQUE"}}},
		},
	}
	want := "CREATE TABLE users (id INTEGER PRIMARY KEY, name VARCHAR(255) NOT NULL, email VARCHAR(255) UNIQUE)"
	if got := stmt.SQL(); got != want {
		t.Errorf("SQL() =\n  %s\nwant:\n  %s", got, want)
	}
}

func TestExpressionSQL(t *testing.T) {
	tests := []struct {
		name string
		expr Expression
		want string
	}{
		{
			name: "between",
			expr: &BetweenExpression{
				Expr:  &Identifier{Name: "age"},
				Lower: &LiteralValue{Value: 18, Type: "INTEGER"},
				Upper: &LiteralValue{Value: 65, Type: "INTEGER"},
			},
			want: "age BETWEEN 18 AND 65",
		},
		{
			name: "not between",
			expr: &BetweenExpression{
				Expr:  &Identifier{Name: "age"},
				Lower: &LiteralValue{Value: 18, Type: "INTEGER"},
				Upper: &LiteralValue{Value: 65, Type: "INTEGER"},
				Not:   true,
			},
			want: "age NOT BETWEEN 18 AND 65",
		},
		{
			name: "in list",
			expr: &InExpression{
				Expr: &Identifier{Name: "status"},
				List: []Expression{
					&LiteralValue{Value: "active", Type: "STRING"},
					&LiteralValue{Value: "pending", Type: "STRING"},
				},
			},
			want: "status IN ('active', 'pending')",
		},
		{
			name: "case expression",
			expr: &CaseExpression{
				WhenClauses: []WhenClause{
					{
						Condition: &BinaryExpression{Left: &Identifier{Name: "x"}, Operator: ">", Right: &LiteralValue{Value: 0, Type: "INTEGER"}},
						Result:    &LiteralValue{Value: "positive", Type: "STRING"},
					},
				},
				ElseClause: &LiteralValue{Value: "non-positive", Type: "STRING"},
			},
			want: "CASE WHEN x > 0 THEN 'positive' ELSE 'non-positive' END",
		},
		{
			name: "cast",
			expr: &CastExpression{
				Expr: &Identifier{Name: "price"},
				Type: "INTEGER",
			},
			want: "CAST(price AS INTEGER)",
		},
		{
			name: "extract",
			expr: &ExtractExpression{
				Field:  "YEAR",
				Source: &Identifier{Name: "created_at"},
			},
			want: "EXTRACT(YEAR FROM created_at)",
		},
		{
			name: "interval",
			expr: &IntervalExpression{Value: "1 day"},
			want: "INTERVAL '1 day'",
		},
		{
			name: "array constructor",
			expr: &ArrayConstructorExpression{
				Elements: []Expression{
					&LiteralValue{Value: 1, Type: "INTEGER"},
					&LiteralValue{Value: 2, Type: "INTEGER"},
				},
			},
			want: "ARRAY[1, 2]",
		},
		{
			name: "unary not",
			expr: &UnaryExpression{Operator: Not, Expr: &Identifier{Name: "active"}},
			want: "NOT active",
		},
		{
			name: "null literal",
			expr: &LiteralValue{Value: nil, Type: "NULL"},
			want: "NULL",
		},
		{
			name: "tuple",
			expr: &TupleExpression{
				Expressions: []Expression{
					&LiteralValue{Value: 1, Type: "INTEGER"},
					&LiteralValue{Value: "a", Type: "STRING"},
				},
			},
			want: "(1, 'a')",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := exprSQL(tt.expr)
			if got != tt.want {
				t.Errorf("SQL() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestWindowFunctionSQL(t *testing.T) {
	stmt := &SelectStatement{
		Columns: []Expression{
			&FunctionCall{
				Name: "ROW_NUMBER",
				Over: &WindowSpec{
					PartitionBy: []Expression{&Identifier{Name: "dept_id"}},
					OrderBy:     []OrderByExpression{{Expression: &Identifier{Name: "salary"}, Ascending: false}},
				},
			},
		},
		From: []TableReference{{Name: "employees"}},
	}
	want := "SELECT ROW_NUMBER() OVER (PARTITION BY dept_id ORDER BY salary DESC) FROM employees"
	if got := stmt.SQL(); got != want {
		t.Errorf("SQL() =\n  %s\nwant:\n  %s", got, want)
	}
}

func TestCTESQL(t *testing.T) {
	inner := &SelectStatement{
		Columns: []Expression{&Identifier{Name: "*"}},
		From:    []TableReference{{Name: "orders"}},
		Where: &BinaryExpression{
			Left:     &Identifier{Name: "total"},
			Operator: ">",
			Right:    &LiteralValue{Value: 100, Type: "INTEGER"},
		},
	}
	stmt := &SelectStatement{
		With: &WithClause{
			CTEs: []*CommonTableExpr{
				{Name: "big_orders", Statement: inner},
			},
		},
		Columns: []Expression{&Identifier{Name: "*"}},
		From:    []TableReference{{Name: "big_orders"}},
	}
	want := "WITH big_orders AS (SELECT * FROM orders WHERE total > 100) SELECT * FROM big_orders"
	if got := stmt.SQL(); got != want {
		t.Errorf("SQL() =\n  %s\nwant:\n  %s", got, want)
	}
}

func TestSetOperationSQL(t *testing.T) {
	left := &SelectStatement{
		Columns: []Expression{&Identifier{Name: "id"}},
		From:    []TableReference{{Name: "a"}},
	}
	right := &SelectStatement{
		Columns: []Expression{&Identifier{Name: "id"}},
		From:    []TableReference{{Name: "b"}},
	}
	stmt := &SetOperation{
		Left:     left,
		Operator: "UNION",
		Right:    right,
		All:      true,
	}
	want := "SELECT id FROM a UNION ALL SELECT id FROM b"
	if got := stmt.SQL(); got != want {
		t.Errorf("SQL() = %s, want %s", got, want)
	}
}

func TestDropStatementSQL(t *testing.T) {
	stmt := &DropStatement{
		ObjectType:  "TABLE",
		IfExists:    true,
		Names:       []string{"users"},
		CascadeType: "CASCADE",
	}
	want := "DROP TABLE IF EXISTS users CASCADE"
	if got := stmt.SQL(); got != want {
		t.Errorf("SQL() = %s, want %s", got, want)
	}
}

func TestTruncateStatementSQL(t *testing.T) {
	stmt := &TruncateStatement{
		Tables:          []string{"users", "orders"},
		RestartIdentity: true,
		CascadeType:     "CASCADE",
	}
	want := "TRUNCATE TABLE users, orders RESTART IDENTITY CASCADE"
	if got := stmt.SQL(); got != want {
		t.Errorf("SQL() = %s, want %s", got, want)
	}
}

func TestAST_SQL(t *testing.T) {
	a := AST{
		Statements: []Statement{
			&SelectStatement{
				Columns: []Expression{&Identifier{Name: "1"}},
			},
			&SelectStatement{
				Columns: []Expression{&Identifier{Name: "2"}},
			},
		},
	}
	want := "SELECT 1;\nSELECT 2"
	if got := a.SQL(); got != want {
		t.Errorf("SQL() = %q, want %q", got, want)
	}
}

func intPtr(i int) *int { return &i }
