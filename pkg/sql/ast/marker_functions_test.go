package ast

import (
	"testing"
)

// TestMarkerFunctions_StatementNodes tests that all statement node types
// correctly implement the Statement interface via their statementNode() marker functions.
// This test achieves comprehensive coverage of all statementNode() implementations.
func TestMarkerFunctions_StatementNodes(t *testing.T) {
	tests := []struct {
		name      string
		statement Statement
		wantType  string
	}{
		{
			name:      "SelectStatement",
			statement: &SelectStatement{},
			wantType:  "SELECT",
		},
		{
			name:      "InsertStatement",
			statement: &InsertStatement{TableName: "test"},
			wantType:  "INSERT",
		},
		{
			name:      "UpdateStatement",
			statement: &UpdateStatement{TableName: "test"},
			wantType:  "UPDATE",
		},
		{
			name:      "DeleteStatement",
			statement: &DeleteStatement{TableName: "test"},
			wantType:  "DELETE",
		},
		{
			name:      "CreateTableStatement",
			statement: &CreateTableStatement{Name: "test"},
			wantType:  "CREATE TABLE",
		},
		{
			name:      "AlterTableStatement",
			statement: &AlterTableStatement{Table: "test"},
			wantType:  "ALTER TABLE",
		},
		{
			name:      "WithClause",
			statement: &WithClause{},
			wantType:  "WITH",
		},
		{
			name:      "CommonTableExpr",
			statement: &CommonTableExpr{Name: "cte1"},
			wantType:  "cte1",
		},
		{
			name: "SetOperation",
			statement: &SetOperation{
				Operator: "UNION",
				Left:     &SelectStatement{},
				Right:    &SelectStatement{},
			},
			wantType: "UNION",
		},
		{
			name:      "TableReference",
			statement: &TableReference{Name: "users"},
			wantType:  "users",
		},
		{
			name:      "WindowSpec",
			statement: &WindowSpec{},
			wantType:  "WINDOW",
		},
		{
			name:      "WindowFrame",
			statement: &WindowFrame{Type: "ROWS"},
			wantType:  "ROWS",
		},
		{
			name:      "CreateIndexStatement",
			statement: &CreateIndexStatement{Name: "idx_test", Table: "test"},
			wantType:  "CREATE INDEX",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify the marker function can be called
			tt.statement.statementNode()

			// Verify it implements Node interface
			var _ Node = tt.statement

			// Verify TokenLiteral returns expected value
			literal := tt.statement.TokenLiteral()
			if literal != tt.wantType {
				t.Errorf("%s.TokenLiteral() = %q, want %q", tt.name, literal, tt.wantType)
			}

			// Verify Children method exists and returns a slice (even if nil/empty)
			children := tt.statement.Children()
			_ = children // Just verify it can be called
		})
	}
}

// TestMarkerFunctions_ExpressionNodes tests that all expression node types
// correctly implement the Expression interface via their expressionNode() marker functions.
func TestMarkerFunctions_ExpressionNodes(t *testing.T) {
	tests := []struct {
		name        string
		expression  Expression
		wantLiteral string
	}{
		{
			name:        "Identifier",
			expression:  &Identifier{Name: "column1"},
			wantLiteral: "column1",
		},
		{
			name:        "FunctionCall",
			expression:  &FunctionCall{Name: "COUNT"},
			wantLiteral: "COUNT",
		},
		{
			name:        "BinaryExpression",
			expression:  &BinaryExpression{Operator: "=", Left: &Identifier{Name: "a"}, Right: &LiteralValue{Value: 1}},
			wantLiteral: "=",
		},
		{
			name:        "LiteralValue",
			expression:  &LiteralValue{Value: 42, Type: "INTEGER"},
			wantLiteral: "42",
		},
		{
			name:        "CaseExpression",
			expression:  &CaseExpression{},
			wantLiteral: "CASE",
		},
		{
			name:        "WhenClause",
			expression:  &WhenClause{Condition: &LiteralValue{Value: true}, Result: &LiteralValue{Value: 1}},
			wantLiteral: "WHEN",
		},
		{
			name:        "ExistsExpression",
			expression:  &ExistsExpression{Subquery: &SelectStatement{}},
			wantLiteral: "EXISTS",
		},
		{
			name:        "InExpression",
			expression:  &InExpression{Expr: &Identifier{Name: "id"}, List: []Expression{}},
			wantLiteral: "IN",
		},
		{
			name:        "BetweenExpression",
			expression:  &BetweenExpression{Expr: &Identifier{Name: "age"}, Lower: &LiteralValue{Value: 18}, Upper: &LiteralValue{Value: 65}},
			wantLiteral: "BETWEEN",
		},
		{
			name:        "ListExpression",
			expression:  &ListExpression{Values: []Expression{}},
			wantLiteral: "LIST",
		},
		{
			name:        "UnaryExpression",
			expression:  &UnaryExpression{Operator: Not, Expr: &LiteralValue{Value: true}},
			wantLiteral: "NOT",
		},
		{
			name:        "JoinClause",
			expression:  &JoinClause{Type: "INNER", Left: TableReference{Name: "t1"}, Right: TableReference{Name: "t2"}},
			wantLiteral: "INNER JOIN",
		},
		{
			name:        "CastExpression",
			expression:  &CastExpression{Expr: &Identifier{Name: "id"}, Type: "INTEGER"},
			wantLiteral: "CAST",
		},
		{
			name:        "ExtractExpression",
			expression:  &ExtractExpression{Field: "YEAR", Source: &Identifier{Name: "date_col"}},
			wantLiteral: "EXTRACT",
		},
		{
			name:        "PositionExpression",
			expression:  &PositionExpression{Substr: &LiteralValue{Value: "abc"}, Str: &LiteralValue{Value: "xabcy"}},
			wantLiteral: "POSITION",
		},
		{
			name:        "SubstringExpression",
			expression:  &SubstringExpression{Str: &LiteralValue{Value: "hello"}, Start: &LiteralValue{Value: 1}},
			wantLiteral: "SUBSTRING",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify the marker function can be called
			tt.expression.expressionNode()

			// Verify it implements Node interface
			var _ Node = tt.expression

			// Verify TokenLiteral returns expected value
			literal := tt.expression.TokenLiteral()
			if literal != tt.wantLiteral {
				t.Errorf("%s.TokenLiteral() = %q, want %q", tt.name, literal, tt.wantLiteral)
			}

			// Verify Children method exists and returns a slice (even if nil/empty)
			children := tt.expression.Children()
			_ = children // Just verify it can be called
		})
	}
}

// TestMarkerFunctions_AlterOperations tests all ALTER operation types
// and their alterOperationNode() marker functions.
func TestMarkerFunctions_AlterOperations(t *testing.T) {
	tests := []struct {
		name      string
		operation AlterOperation
		wantType  string
	}{
		{
			name:      "AlterTableOperation",
			operation: &AlterTableOperation{},
			wantType:  "ALTER TABLE",
		},
		{
			name:      "AlterRoleOperation",
			operation: &AlterRoleOperation{},
			wantType:  "ALTER ROLE",
		},
		{
			name:      "AlterPolicyOperation",
			operation: &AlterPolicyOperation{},
			wantType:  "ALTER POLICY",
		},
		{
			name:      "AlterConnectorOperation",
			operation: &AlterConnectorOperation{},
			wantType:  "ALTER CONNECTOR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify the marker function can be called
			tt.operation.alterOperationNode()

			// Verify it implements Node interface
			var _ Node = tt.operation

			// Verify TokenLiteral returns expected value
			literal := tt.operation.TokenLiteral()
			if literal != tt.wantType {
				t.Errorf("%s.TokenLiteral() = %q, want %q", tt.name, literal, tt.wantType)
			}

			// Verify Children method exists
			children := tt.operation.Children()
			_ = children
		})
	}
}

// TestMarkerFunctions_InterfaceCompliance verifies that all node types
// properly satisfy their respective interfaces.
func TestMarkerFunctions_InterfaceCompliance(t *testing.T) {
	t.Run("Statement interface compliance", func(t *testing.T) {
		var _ Statement = &SelectStatement{}
		var _ Statement = &InsertStatement{}
		var _ Statement = &UpdateStatement{}
		var _ Statement = &DeleteStatement{}
		var _ Statement = &CreateTableStatement{}
		var _ Statement = &AlterTableStatement{}
		var _ Statement = &AlterStatement{}
		var _ Statement = &WithClause{}
		var _ Statement = &CommonTableExpr{}
		var _ Statement = &SetOperation{}
		var _ Statement = &TableReference{}
		var _ Statement = &WindowSpec{}
		var _ Statement = &WindowFrame{}
		var _ Statement = &CreateIndexStatement{}
	})

	t.Run("Expression interface compliance", func(t *testing.T) {
		var _ Expression = &Identifier{}
		var _ Expression = &FunctionCall{}
		var _ Expression = &BinaryExpression{}
		var _ Expression = &LiteralValue{}
		var _ Expression = &CaseExpression{}
		var _ Expression = &WhenClause{}
		var _ Expression = &ExistsExpression{}
		var _ Expression = &InExpression{}
		var _ Expression = &BetweenExpression{}
		var _ Expression = &ListExpression{}
		var _ Expression = &UnaryExpression{}
		var _ Expression = &JoinClause{}
		var _ Expression = &CastExpression{}
		var _ Expression = &ExtractExpression{}
		var _ Expression = &PositionExpression{}
		var _ Expression = &SubstringExpression{}
	})

	t.Run("AlterOperation interface compliance", func(t *testing.T) {
		var _ AlterOperation = &AlterTableOperation{}
		var _ AlterOperation = &AlterRoleOperation{}
		var _ AlterOperation = &AlterPolicyOperation{}
		var _ AlterOperation = &AlterConnectorOperation{}
	})

	t.Run("Node interface is satisfied by all types", func(t *testing.T) {
		// All Statement types must also be Node types
		var _ Node = (Statement)(nil)
		// All Expression types must also be Node types
		var _ Node = (Expression)(nil)
		// All AlterOperation types must also be Node types
		var _ Node = (AlterOperation)(nil)
	})
}

// TestMarkerFunctions_EdgeCases tests edge cases and special scenarios
// for marker functions to ensure complete coverage.
func TestMarkerFunctions_EdgeCases(t *testing.T) {
	t.Run("nil pointer handling", func(t *testing.T) {
		// Ensure marker functions work with zero-value structs
		var sel SelectStatement
		sel.statementNode()
		if literal := sel.TokenLiteral(); literal != "SELECT" {
			t.Errorf("Zero-value SelectStatement.TokenLiteral() = %q, want %q", literal, "SELECT")
		}

		var id Identifier
		id.expressionNode()
		if literal := id.TokenLiteral(); literal != "" {
			t.Errorf("Zero-value Identifier.TokenLiteral() = %q, want empty string", literal)
		}
	})

	t.Run("binary operator with different operators", func(t *testing.T) {
		// Test BinaryExpression with various operators
		ops := []string{"=", "!=", "<", ">", "<=", ">=", "AND", "OR"}
		for _, op := range ops {
			binExpr := &BinaryExpression{
				Operator: op,
				Left:     &Identifier{Name: "a"},
				Right:    &Identifier{Name: "b"},
			}
			binExpr.expressionNode()
			literal := binExpr.TokenLiteral()
			if literal != op {
				t.Errorf("BinaryExpression.TokenLiteral() = %q, want %q", literal, op)
			}
		}
	})

	t.Run("complex nested structures", func(t *testing.T) {
		// Test deeply nested node structures
		stmt := &SelectStatement{
			With: &WithClause{
				CTEs: []*CommonTableExpr{
					{
						Name:      "cte1",
						Statement: &SelectStatement{},
					},
				},
			},
			Columns: []Expression{
				&FunctionCall{
					Name: "COUNT",
					Over: &WindowSpec{
						PartitionBy: []Expression{&Identifier{Name: "dept"}},
					},
				},
			},
		}
		stmt.statementNode()
		children := stmt.Children()
		if len(children) == 0 {
			t.Error("Complex SelectStatement should have children")
		}
	})
}
