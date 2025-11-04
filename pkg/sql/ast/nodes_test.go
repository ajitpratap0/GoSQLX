package ast

import (
	"testing"
)

// Test WithClause node
func TestWithClause(t *testing.T) {
	tests := []struct {
		name         string
		withClause   *WithClause
		wantLiteral  string
		wantChildren int
	}{
		{
			name: "simple CTE",
			withClause: &WithClause{
				Recursive: false,
				CTEs: []*CommonTableExpr{
					{Name: "cte1", Statement: &SelectStatement{}},
				},
			},
			wantLiteral:  "WITH",
			wantChildren: 1,
		},
		{
			name: "recursive CTE",
			withClause: &WithClause{
				Recursive: true,
				CTEs: []*CommonTableExpr{
					{Name: "rec_cte", Statement: &SelectStatement{}},
				},
			},
			wantLiteral:  "WITH",
			wantChildren: 1,
		},
		{
			name: "multiple CTEs",
			withClause: &WithClause{
				Recursive: false,
				CTEs: []*CommonTableExpr{
					{Name: "cte1", Statement: &SelectStatement{}},
					{Name: "cte2", Statement: &SelectStatement{}},
					{Name: "cte3", Statement: &SelectStatement{}},
				},
			},
			wantLiteral:  "WITH",
			wantChildren: 3,
		},
		{
			name: "empty CTEs",
			withClause: &WithClause{
				Recursive: false,
				CTEs:      []*CommonTableExpr{},
			},
			wantLiteral:  "WITH",
			wantChildren: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.withClause.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("WithClause.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.withClause.Children()
			if len(children) != tt.wantChildren {
				t.Errorf("WithClause.Children() count = %d, want %d", len(children), tt.wantChildren)
			}

			// Test that it implements Statement interface
			var _ Statement = tt.withClause
			tt.withClause.statementNode()
		})
	}
}

// Test CommonTableExpr node
func TestCommonTableExpr(t *testing.T) {
	tests := []struct {
		name         string
		cte          *CommonTableExpr
		wantLiteral  string
		wantChildren int
	}{
		{
			name: "simple CTE",
			cte: &CommonTableExpr{
				Name:      "my_cte",
				Statement: &SelectStatement{},
			},
			wantLiteral:  "my_cte",
			wantChildren: 1,
		},
		{
			name: "CTE with columns",
			cte: &CommonTableExpr{
				Name:      "cte_with_cols",
				Columns:   []string{"col1", "col2", "col3"},
				Statement: &SelectStatement{},
			},
			wantLiteral:  "cte_with_cols",
			wantChildren: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.cte.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("CommonTableExpr.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.cte.Children()
			if len(children) != tt.wantChildren {
				t.Errorf("CommonTableExpr.Children() count = %d, want %d", len(children), tt.wantChildren)
			}

			// Test that it implements Statement interface
			var _ Statement = tt.cte
			tt.cte.statementNode()
		})
	}
}

// Test SetOperation node
func TestSetOperation(t *testing.T) {
	tests := []struct {
		name         string
		setOp        *SetOperation
		wantLiteral  string
		wantChildren int
	}{
		{
			name: "UNION",
			setOp: &SetOperation{
				Left:     &SelectStatement{},
				Operator: "UNION",
				Right:    &SelectStatement{},
				All:      false,
			},
			wantLiteral:  "UNION",
			wantChildren: 2,
		},
		{
			name: "UNION ALL",
			setOp: &SetOperation{
				Left:     &SelectStatement{},
				Operator: "UNION",
				Right:    &SelectStatement{},
				All:      true,
			},
			wantLiteral:  "UNION",
			wantChildren: 2,
		},
		{
			name: "EXCEPT",
			setOp: &SetOperation{
				Left:     &SelectStatement{},
				Operator: "EXCEPT",
				Right:    &SelectStatement{},
				All:      false,
			},
			wantLiteral:  "EXCEPT",
			wantChildren: 2,
		},
		{
			name: "INTERSECT",
			setOp: &SetOperation{
				Left:     &SelectStatement{},
				Operator: "INTERSECT",
				Right:    &SelectStatement{},
				All:      false,
			},
			wantLiteral:  "INTERSECT",
			wantChildren: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.setOp.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("SetOperation.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.setOp.Children()
			if len(children) != tt.wantChildren {
				t.Errorf("SetOperation.Children() count = %d, want %d", len(children), tt.wantChildren)
			}

			// Test that it implements Statement interface
			var _ Statement = tt.setOp
			tt.setOp.statementNode()
		})
	}
}

// Test JoinClause node
func TestJoinClause(t *testing.T) {
	tests := []struct {
		name         string
		join         *JoinClause
		wantLiteral  string
		wantChildren int
	}{
		{
			name: "INNER JOIN",
			join: &JoinClause{
				Type:      "INNER",
				Left:      TableReference{Name: "users"},
				Right:     TableReference{Name: "orders"},
				Condition: &Identifier{Name: "condition"},
			},
			wantLiteral:  "INNER JOIN",
			wantChildren: 3,
		},
		{
			name: "LEFT JOIN",
			join: &JoinClause{
				Type:      "LEFT",
				Left:      TableReference{Name: "users"},
				Right:     TableReference{Name: "orders"},
				Condition: &Identifier{Name: "condition"},
			},
			wantLiteral:  "LEFT JOIN",
			wantChildren: 3,
		},
		{
			name: "JOIN without condition",
			join: &JoinClause{
				Type:      "CROSS",
				Left:      TableReference{Name: "users"},
				Right:     TableReference{Name: "orders"},
				Condition: nil,
			},
			wantLiteral:  "CROSS JOIN",
			wantChildren: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.join.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("JoinClause.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.join.Children()
			if len(children) != tt.wantChildren {
				t.Errorf("JoinClause.Children() count = %d, want %d", len(children), tt.wantChildren)
			}

			// Test that it implements Expression interface
			var _ Expression = tt.join
			tt.join.expressionNode()
		})
	}
}

// Test TableReference node
func TestTableReference(t *testing.T) {
	tests := []struct {
		name        string
		tableRef    *TableReference
		wantLiteral string
	}{
		{
			name:        "simple table",
			tableRef:    &TableReference{Name: "users"},
			wantLiteral: "users",
		},
		{
			name:        "table with alias",
			tableRef:    &TableReference{Name: "users", Alias: "u"},
			wantLiteral: "users",
		},
		{
			name:        "qualified table name",
			tableRef:    &TableReference{Name: "schema.table"},
			wantLiteral: "schema.table",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.tableRef.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("TableReference.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.tableRef.Children()
			if children != nil {
				t.Errorf("TableReference.Children() = %v, want nil", children)
			}

			// Test that it implements Statement interface
			var _ Statement = tt.tableRef
			tt.tableRef.statementNode()
		})
	}
}

// Test WindowSpec node
func TestWindowSpec(t *testing.T) {
	tests := []struct {
		name         string
		windowSpec   *WindowSpec
		wantLiteral  string
		wantChildren int
	}{
		{
			name: "simple window spec",
			windowSpec: &WindowSpec{
				Name: "w",
			},
			wantLiteral:  "WINDOW",
			wantChildren: 0,
		},
		{
			name: "with PARTITION BY",
			windowSpec: &WindowSpec{
				Name:        "w",
				PartitionBy: []Expression{&Identifier{Name: "dept"}},
			},
			wantLiteral:  "WINDOW",
			wantChildren: 1,
		},
		{
			name: "with PARTITION BY and ORDER BY",
			windowSpec: &WindowSpec{
				Name:        "w",
				PartitionBy: []Expression{&Identifier{Name: "dept"}},
				OrderBy:     []Expression{&Identifier{Name: "salary"}},
			},
			wantLiteral:  "WINDOW",
			wantChildren: 2,
		},
		{
			name: "with frame clause",
			windowSpec: &WindowSpec{
				Name: "w",
				FrameClause: &WindowFrame{
					Type:  "ROWS",
					Start: WindowFrameBound{Type: "CURRENT ROW"},
				},
			},
			wantLiteral:  "WINDOW",
			wantChildren: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.windowSpec.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("WindowSpec.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.windowSpec.Children()
			if len(children) != tt.wantChildren {
				t.Errorf("WindowSpec.Children() count = %d, want %d", len(children), tt.wantChildren)
			}

			// Test that it implements Statement interface
			var _ Statement = tt.windowSpec
			tt.windowSpec.statementNode()
		})
	}
}

// Test WindowFrame node
func TestWindowFrame(t *testing.T) {
	tests := []struct {
		name        string
		frame       *WindowFrame
		wantLiteral string
	}{
		{
			name: "ROWS frame",
			frame: &WindowFrame{
				Type:  "ROWS",
				Start: WindowFrameBound{Type: "CURRENT ROW"},
			},
			wantLiteral: "ROWS",
		},
		{
			name: "RANGE frame",
			frame: &WindowFrame{
				Type:  "RANGE",
				Start: WindowFrameBound{Type: "UNBOUNDED PRECEDING"},
			},
			wantLiteral: "RANGE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.frame.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("WindowFrame.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.frame.Children()
			if children != nil {
				t.Errorf("WindowFrame.Children() = %v, want nil", children)
			}

			// Test that it implements Statement interface
			var _ Statement = tt.frame
			tt.frame.statementNode()
		})
	}
}

// Test WindowFrameBound node
func TestWindowFrameBound(t *testing.T) {
	tests := []struct {
		name  string
		bound WindowFrameBound
	}{
		{
			name:  "CURRENT ROW",
			bound: WindowFrameBound{Type: "CURRENT ROW"},
		},
		{
			name:  "UNBOUNDED PRECEDING",
			bound: WindowFrameBound{Type: "UNBOUNDED PRECEDING"},
		},
		{
			name:  "UNBOUNDED FOLLOWING",
			bound: WindowFrameBound{Type: "UNBOUNDED FOLLOWING"},
		},
		{
			name:  "with expression",
			bound: WindowFrameBound{Type: "PRECEDING", Value: &LiteralValue{Value: "2"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WindowFrameBound doesn't have TokenLiteral/Children methods
			// Just test that the struct is valid
			if tt.bound.Type == "" {
				t.Error("WindowFrameBound.Type should not be empty")
			}
		})
	}
}

// Test SelectStatement node
func TestSelectStatement(t *testing.T) {
	tests := []struct {
		name        string
		stmt        *SelectStatement
		wantLiteral string
		minChildren int
	}{
		{
			name: "simple SELECT",
			stmt: &SelectStatement{
				Columns: []Expression{&Identifier{Name: "id"}, &Identifier{Name: "name"}},
				From:    []TableReference{{Name: "users"}},
			},
			wantLiteral: "SELECT",
			minChildren: 2,
		},
		{
			name: "SELECT with WHERE",
			stmt: &SelectStatement{
				Columns: []Expression{&Identifier{Name: "id"}},
				From:    []TableReference{{Name: "users"}},
				Where:   &BinaryExpression{Operator: "="},
			},
			wantLiteral: "SELECT",
			minChildren: 2,
		},
		{
			name: "SELECT with GROUP BY and HAVING",
			stmt: &SelectStatement{
				Columns: []Expression{&Identifier{Name: "count"}},
				From:    []TableReference{{Name: "orders"}},
				GroupBy: []Expression{&Identifier{Name: "user_id"}},
				Having:  &BinaryExpression{Operator: ">"},
			},
			wantLiteral: "SELECT",
			minChildren: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.stmt.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("SelectStatement.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.stmt.Children()
			if len(children) < tt.minChildren {
				t.Errorf("SelectStatement.Children() count = %d, want at least %d", len(children), tt.minChildren)
			}

			// Test that it implements Statement interface
			var _ Statement = tt.stmt
			tt.stmt.statementNode()
		})
	}
}

// Test InsertStatement node
func TestInsertStatement(t *testing.T) {
	tests := []struct {
		name        string
		stmt        *InsertStatement
		wantLiteral string
		minChildren int
	}{
		{
			name: "INSERT with values",
			stmt: &InsertStatement{
				TableName: "users",
				Columns:   []Expression{&Identifier{Name: "name"}, &Identifier{Name: "email"}},
				Values:    []Expression{&LiteralValue{Value: "John"}, &LiteralValue{Value: "john@example.com"}},
			},
			wantLiteral: "INSERT",
			minChildren: 2,
		},
		{
			name: "INSERT with SELECT",
			stmt: &InsertStatement{
				TableName: "users",
				Columns:   []Expression{&Identifier{Name: "name"}},
				Query:     &SelectStatement{},
			},
			wantLiteral: "INSERT",
			minChildren: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.stmt.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("InsertStatement.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.stmt.Children()
			if len(children) < tt.minChildren {
				t.Errorf("InsertStatement.Children() count = %d, want at least %d", len(children), tt.minChildren)
			}

			// Test that it implements Statement interface
			var _ Statement = tt.stmt
			tt.stmt.statementNode()
		})
	}
}

// Test UpdateStatement node
func TestUpdateStatement(t *testing.T) {
	tests := []struct {
		name        string
		stmt        *UpdateStatement
		wantLiteral string
		minChildren int
	}{
		{
			name: "simple UPDATE",
			stmt: &UpdateStatement{
				TableName: "users",
				Assignments: []UpdateExpression{
					{Column: &Identifier{Name: "name"}, Value: &LiteralValue{Value: "Jane"}},
				},
			},
			wantLiteral: "UPDATE",
			minChildren: 1,
		},
		{
			name: "UPDATE with WHERE",
			stmt: &UpdateStatement{
				TableName: "users",
				Assignments: []UpdateExpression{
					{Column: &Identifier{Name: "email"}, Value: &LiteralValue{Value: "new@example.com"}},
				},
				Where: &BinaryExpression{Operator: "="},
			},
			wantLiteral: "UPDATE",
			minChildren: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.stmt.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("UpdateStatement.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.stmt.Children()
			if len(children) < tt.minChildren {
				t.Errorf("UpdateStatement.Children() count = %d, want at least %d", len(children), tt.minChildren)
			}

			// Test that it implements Statement interface
			var _ Statement = tt.stmt
			tt.stmt.statementNode()
		})
	}
}

// Test DeleteStatement node
func TestDeleteStatement(t *testing.T) {
	tests := []struct {
		name        string
		stmt        *DeleteStatement
		wantLiteral string
		minChildren int
	}{
		{
			name: "DELETE without WHERE",
			stmt: &DeleteStatement{
				TableName: "users",
			},
			wantLiteral: "DELETE",
			minChildren: 0,
		},
		{
			name: "DELETE with WHERE",
			stmt: &DeleteStatement{
				TableName: "users",
				Where:     &BinaryExpression{Operator: "="},
			},
			wantLiteral: "DELETE",
			minChildren: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.stmt.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("DeleteStatement.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.stmt.Children()
			if len(children) < tt.minChildren {
				t.Errorf("DeleteStatement.Children() count = %d, want at least %d", len(children), tt.minChildren)
			}

			// Test that it implements Statement interface
			var _ Statement = tt.stmt
			tt.stmt.statementNode()
		})
	}
}

// Test Identifier node
func TestIdentifier(t *testing.T) {
	tests := []struct {
		name        string
		identifier  *Identifier
		wantLiteral string
	}{
		{
			name:        "simple identifier",
			identifier:  &Identifier{Name: "id"},
			wantLiteral: "id",
		},
		{
			name:        "qualified identifier",
			identifier:  &Identifier{Table: "users", Name: "id"},
			wantLiteral: "id",
		},
		{
			name:        "asterisk identifier",
			identifier:  &Identifier{Name: "*"},
			wantLiteral: "*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.identifier.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("Identifier.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.identifier.Children()
			if children != nil {
				t.Errorf("Identifier.Children() = %v, want nil", children)
			}

			// Test that it implements Expression interface
			var _ Expression = tt.identifier
			tt.identifier.expressionNode()
		})
	}
}

// Test BinaryExpression node
func TestBinaryExpression(t *testing.T) {
	tests := []struct {
		name         string
		expr         *BinaryExpression
		wantLiteral  string
		wantChildren int
	}{
		{
			name: "equality expression",
			expr: &BinaryExpression{
				Left:     &Identifier{Name: "id"},
				Operator: "=",
				Right:    &LiteralValue{Value: "1"},
			},
			wantLiteral:  "=",
			wantChildren: 2,
		},
		{
			name: "AND expression",
			expr: &BinaryExpression{
				Left:     &BinaryExpression{Operator: "="},
				Operator: "AND",
				Right:    &BinaryExpression{Operator: ">"},
			},
			wantLiteral:  "AND",
			wantChildren: 2,
		},
		{
			name: "arithmetic expression",
			expr: &BinaryExpression{
				Left:     &Identifier{Name: "price"},
				Operator: "*",
				Right:    &LiteralValue{Value: "1.1"},
			},
			wantLiteral:  "*",
			wantChildren: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.expr.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("BinaryExpression.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.expr.Children()
			if len(children) != tt.wantChildren {
				t.Errorf("BinaryExpression.Children() count = %d, want %d", len(children), tt.wantChildren)
			}

			// Test that it implements Expression interface
			var _ Expression = tt.expr
			tt.expr.expressionNode()
		})
	}
}

// Test LiteralValue node
func TestLiteralValue(t *testing.T) {
	tests := []struct {
		name        string
		literal     *LiteralValue
		wantLiteral string
	}{
		{
			name:        "string literal",
			literal:     &LiteralValue{Value: "hello"},
			wantLiteral: "hello",
		},
		{
			name:        "number literal",
			literal:     &LiteralValue{Value: "42"},
			wantLiteral: "42",
		},
		{
			name:        "NULL literal",
			literal:     &LiteralValue{Value: "NULL"},
			wantLiteral: "NULL",
		},
		{
			name:        "boolean literal",
			literal:     &LiteralValue{Value: "TRUE"},
			wantLiteral: "TRUE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.literal.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("LiteralValue.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.literal.Children()
			if children != nil {
				t.Errorf("LiteralValue.Children() = %v, want nil", children)
			}

			// Test that it implements Expression interface
			var _ Expression = tt.literal
			tt.literal.expressionNode()
		})
	}
}

// Test FunctionCall node
func TestFunctionCall(t *testing.T) {
	tests := []struct {
		name         string
		funcCall     *FunctionCall
		wantLiteral  string
		wantChildren int
	}{
		{
			name: "COUNT(*) function",
			funcCall: &FunctionCall{
				Name:      "COUNT",
				Arguments: []Expression{&Identifier{Name: "*"}},
			},
			wantLiteral:  "COUNT",
			wantChildren: 1,
		},
		{
			name: "SUM function with column",
			funcCall: &FunctionCall{
				Name:      "SUM",
				Arguments: []Expression{&Identifier{Name: "amount"}},
			},
			wantLiteral:  "SUM",
			wantChildren: 1,
		},
		{
			name: "window function with OVER clause",
			funcCall: &FunctionCall{
				Name:      "ROW_NUMBER",
				Arguments: []Expression{},
				Over:      &WindowSpec{Name: "w"},
			},
			wantLiteral:  "ROW_NUMBER",
			wantChildren: 1,
		},
		{
			name: "function with multiple arguments",
			funcCall: &FunctionCall{
				Name: "COALESCE",
				Arguments: []Expression{
					&Identifier{Name: "email"},
					&LiteralValue{Value: "N/A"},
				},
			},
			wantLiteral:  "COALESCE",
			wantChildren: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.funcCall.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("FunctionCall.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.funcCall.Children()
			if len(children) != tt.wantChildren {
				t.Errorf("FunctionCall.Children() count = %d, want %d", len(children), tt.wantChildren)
			}

			// Test that it implements Expression interface
			var _ Expression = tt.funcCall
			tt.funcCall.expressionNode()
		})
	}
}

// Test CaseExpression node
func TestCaseExpression(t *testing.T) {
	tests := []struct {
		name         string
		caseExpr     *CaseExpression
		wantLiteral  string
		wantChildren int
	}{
		{
			name: "simple CASE with WHEN clauses",
			caseExpr: &CaseExpression{
				WhenClauses: []WhenClause{
					{Condition: &BinaryExpression{Operator: "="}, Result: &LiteralValue{Value: "1"}},
					{Condition: &BinaryExpression{Operator: ">"}, Result: &LiteralValue{Value: "2"}},
				},
			},
			wantLiteral:  "CASE",
			wantChildren: 2,
		},
		{
			name: "CASE with value and ELSE",
			caseExpr: &CaseExpression{
				Value: &Identifier{Name: "status"},
				WhenClauses: []WhenClause{
					{Condition: &LiteralValue{Value: "active"}, Result: &LiteralValue{Value: "1"}},
				},
				ElseClause: &LiteralValue{Value: "0"},
			},
			wantLiteral:  "CASE",
			wantChildren: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.caseExpr.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("CaseExpression.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.caseExpr.Children()
			if len(children) != tt.wantChildren {
				t.Errorf("CaseExpression.Children() count = %d, want %d", len(children), tt.wantChildren)
			}

			// Test that it implements Expression interface
			var _ Expression = tt.caseExpr
			tt.caseExpr.expressionNode()
		})
	}
}

// Test ExistsExpression node
func TestExistsExpression(t *testing.T) {
	tests := []struct {
		name         string
		existsExpr   *ExistsExpression
		wantLiteral  string
		wantChildren int
	}{
		{
			name: "EXISTS with subquery",
			existsExpr: &ExistsExpression{
				Subquery: &SelectStatement{},
			},
			wantLiteral:  "EXISTS",
			wantChildren: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.existsExpr.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("ExistsExpression.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.existsExpr.Children()
			if len(children) != tt.wantChildren {
				t.Errorf("ExistsExpression.Children() count = %d, want %d", len(children), tt.wantChildren)
			}

			// Test that it implements Expression interface
			var _ Expression = tt.existsExpr
			tt.existsExpr.expressionNode()
		})
	}
}

// Test InExpression node
func TestInExpression(t *testing.T) {
	tests := []struct {
		name         string
		inExpr       *InExpression
		wantLiteral  string
		wantChildren int
	}{
		{
			name: "simple IN expression",
			inExpr: &InExpression{
				Expr: &Identifier{Name: "id"},
				List: []Expression{
					&LiteralValue{Value: "1"},
					&LiteralValue{Value: "2"},
					&LiteralValue{Value: "3"},
				},
				Not: false,
			},
			wantLiteral:  "IN",
			wantChildren: 4,
		},
		{
			name: "NOT IN expression",
			inExpr: &InExpression{
				Expr: &Identifier{Name: "status"},
				List: []Expression{
					&LiteralValue{Value: "deleted"},
					&LiteralValue{Value: "archived"},
				},
				Not: true,
			},
			wantLiteral:  "IN",
			wantChildren: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.inExpr.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("InExpression.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.inExpr.Children()
			if len(children) != tt.wantChildren {
				t.Errorf("InExpression.Children() count = %d, want %d", len(children), tt.wantChildren)
			}

			// Test that it implements Expression interface
			var _ Expression = tt.inExpr
			tt.inExpr.expressionNode()
		})
	}
}

// Test BetweenExpression node
func TestBetweenExpression(t *testing.T) {
	tests := []struct {
		name         string
		betweenExpr  *BetweenExpression
		wantLiteral  string
		wantChildren int
	}{
		{
			name: "simple BETWEEN expression",
			betweenExpr: &BetweenExpression{
				Expr:  &Identifier{Name: "age"},
				Lower: &LiteralValue{Value: "18"},
				Upper: &LiteralValue{Value: "65"},
				Not:   false,
			},
			wantLiteral:  "BETWEEN",
			wantChildren: 3,
		},
		{
			name: "NOT BETWEEN expression",
			betweenExpr: &BetweenExpression{
				Expr:  &Identifier{Name: "price"},
				Lower: &LiteralValue{Value: "100"},
				Upper: &LiteralValue{Value: "500"},
				Not:   true,
			},
			wantLiteral:  "BETWEEN",
			wantChildren: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.betweenExpr.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("BetweenExpression.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.betweenExpr.Children()
			if len(children) != tt.wantChildren {
				t.Errorf("BetweenExpression.Children() count = %d, want %d", len(children), tt.wantChildren)
			}

			// Test that it implements Expression interface
			var _ Expression = tt.betweenExpr
			tt.betweenExpr.expressionNode()
		})
	}
}

// Test UnaryExpression node
func TestUnaryExpression(t *testing.T) {
	tests := []struct {
		name         string
		unaryExpr    *UnaryExpression
		wantChildren int
	}{
		{
			name: "NOT expression",
			unaryExpr: &UnaryExpression{
				Operator: Not,
				Expr:     &Identifier{Name: "active"},
			},
			wantChildren: 1,
		},
		{
			name: "Plus expression",
			unaryExpr: &UnaryExpression{
				Operator: Plus,
				Expr:     &LiteralValue{Value: "10"},
			},
			wantChildren: 1,
		},
		{
			name: "Minus expression",
			unaryExpr: &UnaryExpression{
				Operator: Minus,
				Expr:     &LiteralValue{Value: "5"},
			},
			wantChildren: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test Children
			children := tt.unaryExpr.Children()
			if len(children) != tt.wantChildren {
				t.Errorf("UnaryExpression.Children() count = %d, want %d", len(children), tt.wantChildren)
			}

			// Test that it implements Expression interface
			var _ Expression = tt.unaryExpr
			tt.unaryExpr.expressionNode()
		})
	}
}

// Test CastExpression node
func TestCastExpression(t *testing.T) {
	tests := []struct {
		name         string
		castExpr     *CastExpression
		wantLiteral  string
		wantChildren int
	}{
		{
			name: "CAST to INTEGER",
			castExpr: &CastExpression{
				Expr: &Identifier{Name: "age"},
				Type: "INTEGER",
			},
			wantLiteral:  "CAST",
			wantChildren: 1,
		},
		{
			name: "CAST to VARCHAR",
			castExpr: &CastExpression{
				Expr: &LiteralValue{Value: "123"},
				Type: "VARCHAR(255)",
			},
			wantLiteral:  "CAST",
			wantChildren: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.castExpr.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("CastExpression.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.castExpr.Children()
			if len(children) != tt.wantChildren {
				t.Errorf("CastExpression.Children() count = %d, want %d", len(children), tt.wantChildren)
			}

			// Test that it implements Expression interface
			var _ Expression = tt.castExpr
			tt.castExpr.expressionNode()
		})
	}
}

// Test ExtractExpression node
func TestExtractExpression(t *testing.T) {
	tests := []struct {
		name         string
		extractExpr  *ExtractExpression
		wantLiteral  string
		wantChildren int
	}{
		{
			name: "EXTRACT year",
			extractExpr: &ExtractExpression{
				Field:  "YEAR",
				Source: &Identifier{Name: "created_at"},
			},
			wantLiteral:  "EXTRACT",
			wantChildren: 1,
		},
		{
			name: "EXTRACT month",
			extractExpr: &ExtractExpression{
				Field:  "MONTH",
				Source: &Identifier{Name: "order_date"},
			},
			wantLiteral:  "EXTRACT",
			wantChildren: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.extractExpr.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("ExtractExpression.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.extractExpr.Children()
			if len(children) != tt.wantChildren {
				t.Errorf("ExtractExpression.Children() count = %d, want %d", len(children), tt.wantChildren)
			}

			// Test that it implements Expression interface
			var _ Expression = tt.extractExpr
			tt.extractExpr.expressionNode()
		})
	}
}

// Test ListExpression node
func TestListExpression(t *testing.T) {
	tests := []struct {
		name         string
		listExpr     *ListExpression
		wantLiteral  string
		wantChildren int
	}{
		{
			name: "list with multiple values",
			listExpr: &ListExpression{
				Values: []Expression{
					&LiteralValue{Value: "1"},
					&LiteralValue{Value: "2"},
					&LiteralValue{Value: "3"},
				},
			},
			wantLiteral:  "LIST",
			wantChildren: 3,
		},
		{
			name: "empty list",
			listExpr: &ListExpression{
				Values: []Expression{},
			},
			wantLiteral:  "LIST",
			wantChildren: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.listExpr.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("ListExpression.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.listExpr.Children()
			if len(children) != tt.wantChildren {
				t.Errorf("ListExpression.Children() count = %d, want %d", len(children), tt.wantChildren)
			}

			// Test that it implements Expression interface
			var _ Expression = tt.listExpr
			tt.listExpr.expressionNode()
		})
	}
}

// Test CreateTableStatement node
func TestCreateTableStatement(t *testing.T) {
	tests := []struct {
		name        string
		stmt        *CreateTableStatement
		wantLiteral string
		minChildren int
	}{
		{
			name: "simple CREATE TABLE",
			stmt: &CreateTableStatement{
				Name:    "users",
				Columns: []ColumnDef{},
			},
			wantLiteral: "CREATE TABLE",
			minChildren: 0,
		},
		{
			name: "CREATE TABLE IF NOT EXISTS",
			stmt: &CreateTableStatement{
				Name:        "products",
				IfNotExists: true,
				Columns:     []ColumnDef{},
			},
			wantLiteral: "CREATE TABLE",
			minChildren: 0,
		},
		{
			name: "CREATE TEMPORARY TABLE",
			stmt: &CreateTableStatement{
				Name:      "temp_data",
				Temporary: true,
				Columns:   []ColumnDef{},
			},
			wantLiteral: "CREATE TABLE",
			minChildren: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.stmt.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("CreateTableStatement.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.stmt.Children()
			if len(children) < tt.minChildren {
				t.Errorf("CreateTableStatement.Children() count = %d, want at least %d", len(children), tt.minChildren)
			}

			// Test that it implements Statement interface
			var _ Statement = tt.stmt
			tt.stmt.statementNode()
		})
	}
}

// Test CreateIndexStatement node
func TestCreateIndexStatement(t *testing.T) {
	tests := []struct {
		name        string
		stmt        *CreateIndexStatement
		wantLiteral string
		minChildren int
	}{
		{
			name: "simple CREATE INDEX",
			stmt: &CreateIndexStatement{
				Name:    "idx_users_email",
				Table:   "users",
				Columns: []IndexColumn{},
			},
			wantLiteral: "CREATE INDEX",
			minChildren: 0,
		},
		{
			name: "CREATE UNIQUE INDEX",
			stmt: &CreateIndexStatement{
				Name:    "idx_unique_email",
				Table:   "users",
				Unique:  true,
				Columns: []IndexColumn{},
			},
			wantLiteral: "CREATE INDEX",
			minChildren: 0,
		},
		{
			name: "CREATE INDEX IF NOT EXISTS",
			stmt: &CreateIndexStatement{
				Name:        "idx_products_name",
				Table:       "products",
				IfNotExists: true,
				Columns:     []IndexColumn{},
			},
			wantLiteral: "CREATE INDEX",
			minChildren: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.stmt.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("CreateIndexStatement.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.stmt.Children()
			if len(children) < tt.minChildren {
				t.Errorf("CreateIndexStatement.Children() count = %d, want at least %d", len(children), tt.minChildren)
			}

			// Test that it implements Statement interface
			var _ Statement = tt.stmt
			tt.stmt.statementNode()
		})
	}
}

// Test SubstringExpression node
func TestSubstringExpression(t *testing.T) {
	tests := []struct {
		name          string
		substringExpr *SubstringExpression
		wantLiteral   string
		wantChildren  int
	}{
		{
			name: "SUBSTRING with start",
			substringExpr: &SubstringExpression{
				Str:   &Identifier{Name: "name"},
				Start: &LiteralValue{Value: "1"},
			},
			wantLiteral:  "SUBSTRING",
			wantChildren: 2,
		},
		{
			name: "SUBSTRING with start and length",
			substringExpr: &SubstringExpression{
				Str:    &Identifier{Name: "email"},
				Start:  &LiteralValue{Value: "1"},
				Length: &LiteralValue{Value: "10"},
			},
			wantLiteral:  "SUBSTRING",
			wantChildren: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.substringExpr.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("SubstringExpression.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.substringExpr.Children()
			if len(children) != tt.wantChildren {
				t.Errorf("SubstringExpression.Children() count = %d, want %d", len(children), tt.wantChildren)
			}

			// Test that it implements Expression interface
			var _ Expression = tt.substringExpr
			tt.substringExpr.expressionNode()
		})
	}
}

// Test PositionExpression node
func TestPositionExpression(t *testing.T) {
	tests := []struct {
		name         string
		posExpr      *PositionExpression
		wantLiteral  string
		wantChildren int
	}{
		{
			name: "POSITION expression",
			posExpr: &PositionExpression{
				Substr: &LiteralValue{Value: "@"},
				Str:    &Identifier{Name: "email"},
			},
			wantLiteral:  "POSITION",
			wantChildren: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.posExpr.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("PositionExpression.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.posExpr.Children()
			if len(children) != tt.wantChildren {
				t.Errorf("PositionExpression.Children() count = %d, want %d", len(children), tt.wantChildren)
			}

			// Test that it implements Expression interface
			var _ Expression = tt.posExpr
			tt.posExpr.expressionNode()
		})
	}
}

// Test AlterStatement node
func TestAlterStatement(t *testing.T) {
	tests := []struct {
		name        string
		stmt        *AlterStatement
		wantLiteral string
	}{
		{
			name: "ALTER TABLE statement",
			stmt: &AlterStatement{
				Type:      AlterTypeTable,
				Name:      "users",
				Operation: nil,
			},
			wantLiteral: "ALTER",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.stmt.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("AlterStatement.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test that it implements Statement interface
			var _ Statement = tt.stmt
			tt.stmt.statementNode()
		})
	}
}

// Test AlterTableStatement node
func TestAlterTableStatement(t *testing.T) {
	tests := []struct {
		name        string
		stmt        *AlterTableStatement
		wantLiteral string
	}{
		{
			name: "simple ALTER TABLE",
			stmt: &AlterTableStatement{
				Table:   "users",
				Actions: []AlterTableAction{},
			},
			wantLiteral: "ALTER TABLE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.stmt.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("AlterTableStatement.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test that it implements Statement interface
			var _ Statement = tt.stmt
			tt.stmt.statementNode()
		})
	}
}

// Test OnConflict node
func TestOnConflict(t *testing.T) {
	tests := []struct {
		name        string
		onConflict  *OnConflict
		wantLiteral string
		minChildren int
	}{
		{
			name: "ON CONFLICT DO NOTHING",
			onConflict: &OnConflict{
				Target: []Expression{},
				Action: OnConflictAction{DoNothing: true},
			},
			wantLiteral: "ON CONFLICT",
			minChildren: 0,
		},
		{
			name: "ON CONFLICT DO UPDATE",
			onConflict: &OnConflict{
				Target: []Expression{&Identifier{Name: "email"}},
				Action: OnConflictAction{
					DoUpdate: []UpdateExpression{
						{Column: &Identifier{Name: "updated_at"}, Value: &LiteralValue{Value: "NOW()"}},
					},
				},
			},
			wantLiteral: "ON CONFLICT",
			minChildren: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.onConflict.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("OnConflict.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.onConflict.Children()
			if len(children) < tt.minChildren {
				t.Errorf("OnConflict.Children() count = %d, want at least %d", len(children), tt.minChildren)
			}

			// Test that it implements Expression interface
			var _ Expression = tt.onConflict
			tt.onConflict.expressionNode()
		})
	}
}

// Test WhenClause node
func TestWhenClause(t *testing.T) {
	tests := []struct {
		name         string
		whenClause   WhenClause
		wantLiteral  string
		wantChildren int
	}{
		{
			name: "simple WHEN clause",
			whenClause: WhenClause{
				Condition: &BinaryExpression{Operator: "="},
				Result:    &LiteralValue{Value: "1"},
			},
			wantLiteral:  "WHEN",
			wantChildren: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.whenClause.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("WhenClause.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.whenClause.Children()
			if len(children) != tt.wantChildren {
				t.Errorf("WhenClause.Children() count = %d, want %d", len(children), tt.wantChildren)
			}

			// Test that it implements Expression interface
			var _ Expression = &tt.whenClause
			tt.whenClause.expressionNode()
		})
	}
}

// Test UpdateExpression node
func TestUpdateExpression(t *testing.T) {
	tests := []struct {
		name         string
		updateExpr   *UpdateExpression
		wantChildren int
	}{
		{
			name: "simple update expression",
			updateExpr: &UpdateExpression{
				Column: &Identifier{Name: "name"},
				Value:  &LiteralValue{Value: "John"},
			},
			wantChildren: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test Children
			children := tt.updateExpr.Children()
			if len(children) != tt.wantChildren {
				t.Errorf("UpdateExpression.Children() count = %d, want %d", len(children), tt.wantChildren)
			}

			// Test that it implements Expression interface
			var _ Expression = tt.updateExpr
			tt.updateExpr.expressionNode()
		})
	}
}

// Test IndexColumn node
func TestIndexColumn(t *testing.T) {
	tests := []struct {
		name     string
		indexCol IndexColumn
		wantName string
	}{
		{
			name:     "simple column",
			indexCol: IndexColumn{Column: "email"},
			wantName: "email",
		},
		{
			name:     "column with ASC direction",
			indexCol: IndexColumn{Column: "created_at", Direction: "ASC"},
			wantName: "created_at",
		},
		{
			name:     "column with DESC direction",
			indexCol: IndexColumn{Column: "score", Direction: "DESC"},
			wantName: "score",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test Column field
			if tt.indexCol.Column != tt.wantName {
				t.Errorf("IndexColumn.Column = %v, want %v", tt.indexCol.Column, tt.wantName)
			}

			// Test TokenLiteral
			if got := tt.indexCol.TokenLiteral(); got != tt.wantName {
				t.Errorf("IndexColumn.TokenLiteral() = %v, want %v", got, tt.wantName)
			}

			// Test that it implements Expression interface
			var _ Expression = &tt.indexCol
			tt.indexCol.expressionNode()
		})
	}
}

// Test ColumnDef node
func TestColumnDef(t *testing.T) {
	tests := []struct {
		name      string
		columnDef ColumnDef
		wantName  string
	}{
		{
			name:      "simple column",
			columnDef: ColumnDef{Name: "id", Type: "INTEGER"},
			wantName:  "id",
		},
		{
			name:      "column with constraints",
			columnDef: ColumnDef{Name: "email", Type: "VARCHAR(255)", Constraints: []ColumnConstraint{}},
			wantName:  "email",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test Name field
			if tt.columnDef.Name != tt.wantName {
				t.Errorf("ColumnDef.Name = %v, want %v", tt.columnDef.Name, tt.wantName)
			}

			// Test TokenLiteral
			if got := tt.columnDef.TokenLiteral(); got != tt.wantName {
				t.Errorf("ColumnDef.TokenLiteral() = %v, want %v", got, tt.wantName)
			}

			// Test that it implements Expression interface
			var _ Expression = &tt.columnDef
			tt.columnDef.expressionNode()
		})
	}
}

// Test UpsertClause node
func TestUpsertClause(t *testing.T) {
	tests := []struct {
		name         string
		upsert       *UpsertClause
		wantLiteral  string
		wantChildren int
	}{
		{
			name: "simple UPSERT",
			upsert: &UpsertClause{
				Updates: []UpdateExpression{
					{Column: &Identifier{Name: "count"}, Value: &LiteralValue{Value: "1"}},
				},
			},
			wantLiteral:  "ON DUPLICATE KEY UPDATE",
			wantChildren: 1,
		},
		{
			name: "UPSERT with multiple updates",
			upsert: &UpsertClause{
				Updates: []UpdateExpression{
					{Column: &Identifier{Name: "count"}, Value: &LiteralValue{Value: "1"}},
					{Column: &Identifier{Name: "updated_at"}, Value: &LiteralValue{Value: "NOW()"}},
				},
			},
			wantLiteral:  "ON DUPLICATE KEY UPDATE",
			wantChildren: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.upsert.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("UpsertClause.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.upsert.Children()
			if len(children) != tt.wantChildren {
				t.Errorf("UpsertClause.Children() count = %d, want %d", len(children), tt.wantChildren)
			}

			// Test that it implements Expression interface
			var _ Expression = tt.upsert
			tt.upsert.expressionNode()
		})
	}
}

// Test Values node
func TestValues(t *testing.T) {
	tests := []struct {
		name         string
		values       *Values
		wantLiteral  string
		wantChildren int
	}{
		{
			name: "single row",
			values: &Values{
				Rows: [][]Expression{
					{&LiteralValue{Value: "1"}, &LiteralValue{Value: "John"}},
				},
			},
			wantLiteral:  "VALUES",
			wantChildren: 2,
		},
		{
			name: "multiple rows",
			values: &Values{
				Rows: [][]Expression{
					{&LiteralValue{Value: "1"}, &LiteralValue{Value: "John"}},
					{&LiteralValue{Value: "2"}, &LiteralValue{Value: "Jane"}},
					{&LiteralValue{Value: "3"}, &LiteralValue{Value: "Bob"}},
				},
			},
			wantLiteral:  "VALUES",
			wantChildren: 6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.values.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("Values.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.values.Children()
			if len(children) != tt.wantChildren {
				t.Errorf("Values.Children() count = %d, want %d", len(children), tt.wantChildren)
			}

			// Test that it implements Statement interface
			var _ Statement = tt.values
			tt.values.statementNode()
		})
	}
}

// Test ColumnConstraint node
func TestColumnConstraint(t *testing.T) {
	tests := []struct {
		name        string
		constraint  *ColumnConstraint
		wantLiteral string
		minChildren int
	}{
		{
			name:        "NOT NULL constraint",
			constraint:  &ColumnConstraint{Type: "NOT NULL"},
			wantLiteral: "NOT NULL",
			minChildren: 0,
		},
		{
			name:        "PRIMARY KEY constraint",
			constraint:  &ColumnConstraint{Type: "PRIMARY KEY"},
			wantLiteral: "PRIMARY KEY",
			minChildren: 0,
		},
		{
			name: "DEFAULT constraint",
			constraint: &ColumnConstraint{
				Type:    "DEFAULT",
				Default: &LiteralValue{Value: "0"},
			},
			wantLiteral: "DEFAULT",
			minChildren: 1,
		},
		{
			name: "CHECK constraint",
			constraint: &ColumnConstraint{
				Type:  "CHECK",
				Check: &BinaryExpression{Operator: ">"},
			},
			wantLiteral: "CHECK",
			minChildren: 1,
		},
		{
			name:        "AUTO_INCREMENT constraint",
			constraint:  &ColumnConstraint{Type: "AUTO_INCREMENT", AutoIncrement: true},
			wantLiteral: "AUTO_INCREMENT",
			minChildren: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.constraint.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("ColumnConstraint.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.constraint.Children()
			if len(children) < tt.minChildren {
				t.Errorf("ColumnConstraint.Children() count = %d, want at least %d", len(children), tt.minChildren)
			}

			// Test that it implements Expression interface
			var _ Expression = tt.constraint
			tt.constraint.expressionNode()
		})
	}
}

// Test TableConstraint node
func TestTableConstraint(t *testing.T) {
	tests := []struct {
		name        string
		constraint  *TableConstraint
		wantLiteral string
		minChildren int
	}{
		{
			name: "PRIMARY KEY constraint",
			constraint: &TableConstraint{
				Type:    "PRIMARY KEY",
				Columns: []string{"id"},
			},
			wantLiteral: "PRIMARY KEY",
			minChildren: 0,
		},
		{
			name: "UNIQUE constraint",
			constraint: &TableConstraint{
				Name:    "unique_email",
				Type:    "UNIQUE",
				Columns: []string{"email"},
			},
			wantLiteral: "UNIQUE",
			minChildren: 0,
		},
		{
			name: "FOREIGN KEY constraint",
			constraint: &TableConstraint{
				Type:    "FOREIGN KEY",
				Columns: []string{"user_id"},
				References: &ReferenceDefinition{
					Table:   "users",
					Columns: []string{"id"},
				},
			},
			wantLiteral: "FOREIGN KEY",
			minChildren: 1,
		},
		{
			name: "CHECK constraint",
			constraint: &TableConstraint{
				Type:  "CHECK",
				Check: &BinaryExpression{Operator: ">"},
			},
			wantLiteral: "CHECK",
			minChildren: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.constraint.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("TableConstraint.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.constraint.Children()
			if len(children) < tt.minChildren {
				t.Errorf("TableConstraint.Children() count = %d, want at least %d", len(children), tt.minChildren)
			}

			// Test that it implements Expression interface
			var _ Expression = tt.constraint
			tt.constraint.expressionNode()
		})
	}
}

// Test ReferenceDefinition node
func TestReferenceDefinition(t *testing.T) {
	tests := []struct {
		name        string
		ref         *ReferenceDefinition
		wantLiteral string
	}{
		{
			name: "simple REFERENCES",
			ref: &ReferenceDefinition{
				Table:   "users",
				Columns: []string{"id"},
			},
			wantLiteral: "REFERENCES",
		},
		{
			name: "REFERENCES with ON DELETE CASCADE",
			ref: &ReferenceDefinition{
				Table:    "users",
				Columns:  []string{"id"},
				OnDelete: "CASCADE",
			},
			wantLiteral: "REFERENCES",
		},
		{
			name: "REFERENCES with ON UPDATE SET NULL",
			ref: &ReferenceDefinition{
				Table:    "departments",
				Columns:  []string{"id"},
				OnUpdate: "SET NULL",
			},
			wantLiteral: "REFERENCES",
		},
		{
			name: "REFERENCES with MATCH FULL",
			ref: &ReferenceDefinition{
				Table:   "categories",
				Columns: []string{"id"},
				Match:   "FULL",
			},
			wantLiteral: "REFERENCES",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.ref.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("ReferenceDefinition.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.ref.Children()
			if children != nil {
				t.Errorf("ReferenceDefinition.Children() = %v, want nil", children)
			}

			// Test that it implements Expression interface
			var _ Expression = tt.ref
			tt.ref.expressionNode()
		})
	}
}

// Test PartitionBy node
func TestPartitionBy(t *testing.T) {
	tests := []struct {
		name         string
		partition    *PartitionBy
		wantLiteral  string
		wantChildren int
	}{
		{
			name: "RANGE partition",
			partition: &PartitionBy{
				Type:    "RANGE",
				Columns: []string{"created_at"},
			},
			wantLiteral:  "PARTITION BY",
			wantChildren: 0,
		},
		{
			name: "LIST partition",
			partition: &PartitionBy{
				Type:    "LIST",
				Columns: []string{"region"},
			},
			wantLiteral:  "PARTITION BY",
			wantChildren: 0,
		},
		{
			name: "HASH partition",
			partition: &PartitionBy{
				Type:    "HASH",
				Columns: []string{"user_id"},
			},
			wantLiteral:  "PARTITION BY",
			wantChildren: 0,
		},
		{
			name: "partition with boundary",
			partition: &PartitionBy{
				Type:     "RANGE",
				Columns:  []string{"created_at"},
				Boundary: []Expression{&LiteralValue{Value: "2024-01-01"}},
			},
			wantLiteral:  "PARTITION BY",
			wantChildren: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.partition.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("PartitionBy.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.partition.Children()
			if len(children) != tt.wantChildren {
				t.Errorf("PartitionBy.Children() count = %d, want %d", len(children), tt.wantChildren)
			}

			// Test that it implements Expression interface
			var _ Expression = tt.partition
			tt.partition.expressionNode()
		})
	}
}

// Test TableOption node
func TestTableOption(t *testing.T) {
	tests := []struct {
		name      string
		option    TableOption
		wantName  string
		wantValue string
	}{
		{
			name:      "ENGINE option",
			option:    TableOption{Name: "ENGINE", Value: "InnoDB"},
			wantName:  "ENGINE",
			wantValue: "InnoDB",
		},
		{
			name:      "CHARSET option",
			option:    TableOption{Name: "CHARSET", Value: "utf8mb4"},
			wantName:  "CHARSET",
			wantValue: "utf8mb4",
		},
		{
			name:      "COLLATE option",
			option:    TableOption{Name: "COLLATE", Value: "utf8mb4_unicode_ci"},
			wantName:  "COLLATE",
			wantValue: "utf8mb4_unicode_ci",
		},
		{
			name:      "AUTO_INCREMENT option",
			option:    TableOption{Name: "AUTO_INCREMENT", Value: "1000"},
			wantName:  "AUTO_INCREMENT",
			wantValue: "1000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test Name field
			if tt.option.Name != tt.wantName {
				t.Errorf("TableOption.Name = %v, want %v", tt.option.Name, tt.wantName)
			}

			// Test Value field
			if tt.option.Value != tt.wantValue {
				t.Errorf("TableOption.Value = %v, want %v", tt.option.Value, tt.wantValue)
			}
		})
	}
}
