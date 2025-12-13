package ast

import (
	"testing"
)

// TestStatementNodeMarkers tests all statementNode() marker methods
func TestStatementNodeMarkers(t *testing.T) {
	// Test all types that implement statementNode()
	tests := []struct {
		name string
		stmt Statement
	}{
		{"WithClause", &WithClause{}},
		{"CommonTableExpr", &CommonTableExpr{}},
		{"SetOperation", &SetOperation{}},
		{"TableReference", &TableReference{}},
		{"WindowSpec", &WindowSpec{}},
		{"WindowFrame", &WindowFrame{}},
		{"SelectStatement", &SelectStatement{}},
		{"InsertStatement", &InsertStatement{}},
		{"UpdateStatement", &UpdateStatement{}},
		{"DeleteStatement", &DeleteStatement{}},
		{"CreateTableStatement", &CreateTableStatement{}},
		{"AlterTableStatement", &AlterTableStatement{}},
		{"CreateIndexStatement", &CreateIndexStatement{}},
		{"MergeStatement", &MergeStatement{}},
		{"CreateViewStatement", &CreateViewStatement{}},
		{"CreateMaterializedViewStatement", &CreateMaterializedViewStatement{}},
		{"RefreshMaterializedViewStatement", &RefreshMaterializedViewStatement{}},
		{"DropStatement", &DropStatement{}},
		{"TruncateStatement", &TruncateStatement{}},
		{"Values", &Values{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Call statementNode() to exercise the marker method
			tt.stmt.statementNode()
			// Just verify it doesn't panic - marker methods have no return value
		})
	}
}

// TestExpressionNodeMarkers tests all expressionNode() marker methods
func TestExpressionNodeMarkers(t *testing.T) {
	tests := []struct {
		name string
		expr Expression
	}{
		{"JoinClause", &JoinClause{}},
		{"OrderByExpression", &OrderByExpression{}},
		{"WindowFrameBound", &WindowFrameBound{}},
		{"FetchClause", &FetchClause{}},
		{"RollupExpression", &RollupExpression{}},
		{"CubeExpression", &CubeExpression{}},
		{"GroupingSetsExpression", &GroupingSetsExpression{}},
		{"Identifier", &Identifier{}},
		{"FunctionCall", &FunctionCall{}},
		{"CaseExpression", &CaseExpression{}},
		{"WhenClause", &WhenClause{}},
		{"ExistsExpression", &ExistsExpression{}},
		{"InExpression", &InExpression{}},
		{"SubqueryExpression", &SubqueryExpression{}},
		{"AnyExpression", &AnyExpression{}},
		{"AllExpression", &AllExpression{}},
		{"BetweenExpression", &BetweenExpression{}},
		{"BinaryExpression", &BinaryExpression{}},
		{"LiteralValue", &LiteralValue{}},
		{"ListExpression", &ListExpression{}},
		{"UnaryExpression", &UnaryExpression{}},
		{"CastExpression", &CastExpression{}},
		{"ExtractExpression", &ExtractExpression{}},
		{"PositionExpression", &PositionExpression{}},
		{"SubstringExpression", &SubstringExpression{}},
		{"OnConflict", &OnConflict{}},
		{"UpsertClause", &UpsertClause{}},
		{"ColumnDef", &ColumnDef{}},
		{"ColumnConstraint", &ColumnConstraint{}},
		{"TableConstraint", &TableConstraint{}},
		{"ReferenceDefinition", &ReferenceDefinition{}},
		{"PartitionBy", &PartitionBy{}},
		{"TableOption", &TableOption{}},
		{"UpdateExpression", &UpdateExpression{}},
		{"AlterTableAction", &AlterTableAction{}},
		{"IndexColumn", &IndexColumn{}},
		{"MergeWhenClause", &MergeWhenClause{}},
		{"MergeAction", &MergeAction{}},
		{"SetClause", &SetClause{}},
		{"PartitionDefinition", &PartitionDefinition{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.expr.expressionNode()
		})
	}
}

// TestTokenLiteralMethods tests TokenLiteral() for all node types
func TestTokenLiteralMethods(t *testing.T) {
	tests := []struct {
		name     string
		node     Node
		expected string
	}{
		// Statement types
		{"WithClause", WithClause{}, "WITH"},
		{"CommonTableExpr", CommonTableExpr{Name: "cte_name"}, "cte_name"},
		{"SetOperation_UNION", SetOperation{Operator: "UNION"}, "UNION"},
		{"SetOperation_EXCEPT", SetOperation{Operator: "EXCEPT"}, "EXCEPT"},
		{"SetOperation_INTERSECT", SetOperation{Operator: "INTERSECT"}, "INTERSECT"},
		{"JoinClause_INNER", JoinClause{Type: "INNER"}, "INNER JOIN"},
		{"JoinClause_LEFT", JoinClause{Type: "LEFT"}, "LEFT JOIN"},
		{"TableReference", TableReference{Name: "users"}, "users"},
		{"OrderByExpression", &OrderByExpression{}, "ORDER BY"},
		{"WindowSpec", WindowSpec{}, "WINDOW"},
		{"WindowFrame_ROWS", WindowFrame{Type: "ROWS"}, "ROWS"},
		{"WindowFrame_RANGE", WindowFrame{Type: "RANGE"}, "RANGE"},
		{"WindowFrameBound_type", WindowFrameBound{Type: "CURRENT ROW"}, "CURRENT ROW"},
		{"WindowFrameBound_empty", WindowFrameBound{}, "BOUND"},
		{"SelectStatement", SelectStatement{}, "SELECT"},
		{"FetchClause", FetchClause{}, "FETCH"},
		{"RollupExpression", RollupExpression{}, "ROLLUP"},
		{"CubeExpression", CubeExpression{}, "CUBE"},
		{"GroupingSetsExpression", GroupingSetsExpression{}, "GROUPING SETS"},
		{"Identifier", Identifier{Name: "column_name"}, "column_name"},
		{"FunctionCall", FunctionCall{Name: "COUNT"}, "COUNT"},
		{"CaseExpression", CaseExpression{}, "CASE"},
		{"WhenClause", WhenClause{}, "WHEN"},
		{"ExistsExpression", ExistsExpression{}, "EXISTS"},
		{"InExpression", InExpression{}, "IN"},
		{"SubqueryExpression", SubqueryExpression{}, "SUBQUERY"},
		{"AnyExpression", AnyExpression{}, "ANY"},
		{"AllExpression", AllExpression{}, "ALL"},
		{"BetweenExpression", BetweenExpression{}, "BETWEEN"},
		{"BinaryExpression_operator", &BinaryExpression{Operator: "="}, "="},
		{"LiteralValue_int", LiteralValue{Value: 42}, "42"},
		{"LiteralValue_string", LiteralValue{Value: "hello"}, "hello"},
		{"ListExpression", ListExpression{}, "LIST"},
		{"CastExpression", CastExpression{}, "CAST"},
		{"ExtractExpression", ExtractExpression{}, "EXTRACT"},
		{"PositionExpression", PositionExpression{}, "POSITION"},
		{"SubstringExpression", SubstringExpression{}, "SUBSTRING"},
		{"InsertStatement", InsertStatement{}, "INSERT"},
		{"OnConflict", OnConflict{}, "ON CONFLICT"},
		{"UpsertClause", UpsertClause{}, "ON DUPLICATE KEY UPDATE"},
		{"Values", Values{}, "VALUES"},
		{"UpdateStatement", UpdateStatement{}, "UPDATE"},
		{"CreateTableStatement", CreateTableStatement{}, "CREATE TABLE"},
		{"ColumnDef", ColumnDef{Name: "id"}, "id"},
		{"ColumnConstraint_NOT_NULL", ColumnConstraint{Type: "NOT NULL"}, "NOT NULL"},
		{"TableConstraint_PRIMARY_KEY", TableConstraint{Type: "PRIMARY KEY"}, "PRIMARY KEY"},
		{"ReferenceDefinition", ReferenceDefinition{}, "REFERENCES"},
		{"PartitionBy", PartitionBy{}, "PARTITION BY"},
		{"TableOption", TableOption{Name: "ENGINE"}, "ENGINE"},
		{"UpdateExpression", UpdateExpression{}, "="},
		{"DeleteStatement", DeleteStatement{}, "DELETE"},
		{"AlterTableStatement", AlterTableStatement{}, "ALTER TABLE"},
		{"AlterTableAction", AlterTableAction{Type: "ADD COLUMN"}, "ADD COLUMN"},
		{"CreateIndexStatement", CreateIndexStatement{}, "CREATE INDEX"},
		{"IndexColumn", IndexColumn{Column: "user_id"}, "user_id"},
		{"MergeStatement", MergeStatement{}, "MERGE"},
		{"MergeWhenClause_MATCHED", MergeWhenClause{Type: "MATCHED"}, "WHEN MATCHED"},
		{"MergeWhenClause_NOT_MATCHED", MergeWhenClause{Type: "NOT_MATCHED"}, "WHEN NOT_MATCHED"},
		{"MergeAction_UPDATE", MergeAction{ActionType: "UPDATE"}, "UPDATE"},
		{"MergeAction_INSERT", MergeAction{ActionType: "INSERT"}, "INSERT"},
		{"SetClause", SetClause{Column: "name"}, "name"},
		{"CreateViewStatement", CreateViewStatement{}, "CREATE VIEW"},
		{"CreateMaterializedViewStatement", CreateMaterializedViewStatement{}, "CREATE MATERIALIZED VIEW"},
		{"RefreshMaterializedViewStatement", RefreshMaterializedViewStatement{}, "REFRESH MATERIALIZED VIEW"},
		{"DropStatement_TABLE", DropStatement{ObjectType: "TABLE"}, "DROP TABLE"},
		{"DropStatement_VIEW", DropStatement{ObjectType: "VIEW"}, "DROP VIEW"},
		{"TruncateStatement", TruncateStatement{}, "TRUNCATE TABLE"},
		{"PartitionDefinition", PartitionDefinition{Name: "p0"}, "PARTITION p0"},
		{"AST", AST{}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.node.TokenLiteral()
			if result != tt.expected {
				t.Errorf("TokenLiteral() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestChildrenMethods tests Children() for all node types
func TestChildrenMethods(t *testing.T) {
	// Create test expressions and statements for use in tests
	testIdent := &Identifier{Name: "test"}
	testStmt := &SelectStatement{}
	testExpr := &LiteralValue{Value: 1}

	t.Run("WithClause", func(t *testing.T) {
		node := &WithClause{
			CTEs: []*CommonTableExpr{
				{Name: "cte1"},
				{Name: "cte2"},
			},
		}
		children := node.Children()
		if len(children) != 2 {
			t.Errorf("Children() returned %d, want 2", len(children))
		}
	})

	t.Run("CommonTableExpr", func(t *testing.T) {
		node := &CommonTableExpr{
			Name:      "cte",
			Statement: testStmt,
		}
		children := node.Children()
		if len(children) != 1 {
			t.Errorf("Children() returned %d, want 1", len(children))
		}
	})

	t.Run("SetOperation", func(t *testing.T) {
		node := &SetOperation{
			Left:  testStmt,
			Right: testStmt,
		}
		children := node.Children()
		if len(children) != 2 {
			t.Errorf("Children() returned %d, want 2", len(children))
		}
	})

	t.Run("JoinClause_with_condition", func(t *testing.T) {
		node := &JoinClause{
			Left:      TableReference{Name: "t1"},
			Right:     TableReference{Name: "t2"},
			Condition: testIdent,
		}
		children := node.Children()
		if len(children) != 3 {
			t.Errorf("Children() returned %d, want 3", len(children))
		}
	})

	t.Run("JoinClause_without_condition", func(t *testing.T) {
		node := &JoinClause{
			Left:  TableReference{Name: "t1"},
			Right: TableReference{Name: "t2"},
		}
		children := node.Children()
		if len(children) != 2 {
			t.Errorf("Children() returned %d, want 2", len(children))
		}
	})

	t.Run("TableReference", func(t *testing.T) {
		node := TableReference{Name: "users"}
		children := node.Children()
		if children != nil {
			t.Errorf("Children() should be nil for TableReference")
		}
	})

	t.Run("OrderByExpression_with_expr", func(t *testing.T) {
		node := &OrderByExpression{Expression: testIdent}
		children := node.Children()
		if len(children) != 1 {
			t.Errorf("Children() returned %d, want 1", len(children))
		}
	})

	t.Run("OrderByExpression_without_expr", func(t *testing.T) {
		node := &OrderByExpression{}
		children := node.Children()
		if children != nil {
			t.Errorf("Children() should be nil when Expression is nil")
		}
	})

	t.Run("WindowSpec", func(t *testing.T) {
		node := &WindowSpec{
			PartitionBy: []Expression{testIdent},
			OrderBy:     []OrderByExpression{{Expression: testIdent}},
			FrameClause: &WindowFrame{Type: "ROWS"},
		}
		children := node.Children()
		if len(children) != 3 {
			t.Errorf("Children() returned %d, want 3", len(children))
		}
	})

	t.Run("WindowFrame", func(t *testing.T) {
		node := WindowFrame{}
		children := node.Children()
		if children != nil {
			t.Errorf("Children() should be nil for WindowFrame")
		}
	})

	t.Run("WindowFrameBound_with_value", func(t *testing.T) {
		node := WindowFrameBound{Value: testExpr}
		children := node.Children()
		if len(children) != 1 {
			t.Errorf("Children() returned %d, want 1", len(children))
		}
	})

	t.Run("WindowFrameBound_without_value", func(t *testing.T) {
		node := WindowFrameBound{}
		children := node.Children()
		if children != nil {
			t.Errorf("Children() should be nil when Value is nil")
		}
	})

	t.Run("FetchClause", func(t *testing.T) {
		node := FetchClause{}
		children := node.Children()
		if children != nil {
			t.Errorf("Children() should be nil for FetchClause")
		}
	})

	t.Run("RollupExpression", func(t *testing.T) {
		node := RollupExpression{Expressions: []Expression{testIdent, testIdent}}
		children := node.Children()
		if len(children) != 2 {
			t.Errorf("Children() returned %d, want 2", len(children))
		}
	})

	t.Run("CubeExpression", func(t *testing.T) {
		node := CubeExpression{Expressions: []Expression{testIdent}}
		children := node.Children()
		if len(children) != 1 {
			t.Errorf("Children() returned %d, want 1", len(children))
		}
	})

	t.Run("GroupingSetsExpression", func(t *testing.T) {
		node := GroupingSetsExpression{
			Sets: [][]Expression{{testIdent}, {testIdent, testIdent}},
		}
		children := node.Children()
		if len(children) != 3 {
			t.Errorf("Children() returned %d, want 3", len(children))
		}
	})

	t.Run("Identifier", func(t *testing.T) {
		node := Identifier{Name: "col"}
		children := node.Children()
		if children != nil {
			t.Errorf("Children() should be nil for Identifier")
		}
	})

	t.Run("FunctionCall", func(t *testing.T) {
		node := FunctionCall{
			Name:      "COUNT",
			Arguments: []Expression{testIdent},
			Over:      &WindowSpec{},
			Filter:    testExpr,
		}
		children := node.Children()
		if len(children) != 3 {
			t.Errorf("Children() returned %d, want 3", len(children))
		}
	})

	t.Run("CaseExpression", func(t *testing.T) {
		node := CaseExpression{
			Value:       testExpr,
			WhenClauses: []WhenClause{{Condition: testExpr, Result: testExpr}},
			ElseClause:  testExpr,
		}
		children := node.Children()
		if len(children) != 3 {
			t.Errorf("Children() returned %d, want 3", len(children))
		}
	})

	t.Run("WhenClause", func(t *testing.T) {
		node := WhenClause{Condition: testExpr, Result: testExpr}
		children := node.Children()
		if len(children) != 2 {
			t.Errorf("Children() returned %d, want 2", len(children))
		}
	})

	t.Run("ExistsExpression", func(t *testing.T) {
		node := ExistsExpression{Subquery: testStmt}
		children := node.Children()
		if len(children) != 1 {
			t.Errorf("Children() returned %d, want 1", len(children))
		}
	})

	t.Run("InExpression_with_list", func(t *testing.T) {
		node := InExpression{
			Expr: testIdent,
			List: []Expression{testExpr, testExpr},
		}
		children := node.Children()
		if len(children) != 3 { // Expr + 2 list items
			t.Errorf("Children() returned %d, want 3", len(children))
		}
	})

	t.Run("InExpression_with_subquery", func(t *testing.T) {
		node := InExpression{
			Expr:     testIdent,
			Subquery: testStmt,
		}
		children := node.Children()
		if len(children) != 2 {
			t.Errorf("Children() returned %d, want 2", len(children))
		}
	})

	t.Run("SubqueryExpression", func(t *testing.T) {
		node := SubqueryExpression{Subquery: testStmt}
		children := node.Children()
		if len(children) != 1 {
			t.Errorf("Children() returned %d, want 1", len(children))
		}
	})

	t.Run("AnyExpression", func(t *testing.T) {
		node := AnyExpression{Expr: testIdent, Subquery: testStmt}
		children := node.Children()
		if len(children) != 2 {
			t.Errorf("Children() returned %d, want 2", len(children))
		}
	})

	t.Run("AllExpression", func(t *testing.T) {
		node := AllExpression{Expr: testIdent, Subquery: testStmt}
		children := node.Children()
		if len(children) != 2 {
			t.Errorf("Children() returned %d, want 2", len(children))
		}
	})

	t.Run("BetweenExpression", func(t *testing.T) {
		node := BetweenExpression{Expr: testIdent, Lower: testExpr, Upper: testExpr}
		children := node.Children()
		if len(children) != 3 {
			t.Errorf("Children() returned %d, want 3", len(children))
		}
	})

	t.Run("BinaryExpression", func(t *testing.T) {
		node := BinaryExpression{Left: testIdent, Right: testExpr}
		children := node.Children()
		if len(children) != 2 {
			t.Errorf("Children() returned %d, want 2", len(children))
		}
	})

	t.Run("LiteralValue", func(t *testing.T) {
		node := LiteralValue{Value: 42}
		children := node.Children()
		if children != nil {
			t.Errorf("Children() should be nil for LiteralValue")
		}
	})

	t.Run("ListExpression", func(t *testing.T) {
		node := ListExpression{Values: []Expression{testExpr, testExpr}}
		children := node.Children()
		if len(children) != 2 {
			t.Errorf("Children() returned %d, want 2", len(children))
		}
	})

	t.Run("UnaryExpression", func(t *testing.T) {
		node := UnaryExpression{Expr: testIdent}
		children := node.Children()
		if len(children) != 1 {
			t.Errorf("Children() returned %d, want 1", len(children))
		}
	})

	t.Run("CastExpression", func(t *testing.T) {
		node := CastExpression{Expr: testIdent}
		children := node.Children()
		if len(children) != 1 {
			t.Errorf("Children() returned %d, want 1", len(children))
		}
	})

	t.Run("ExtractExpression", func(t *testing.T) {
		node := ExtractExpression{Source: testIdent}
		children := node.Children()
		if len(children) != 1 {
			t.Errorf("Children() returned %d, want 1", len(children))
		}
	})

	t.Run("PositionExpression", func(t *testing.T) {
		node := PositionExpression{Substr: testIdent, Str: testIdent}
		children := node.Children()
		if len(children) != 2 {
			t.Errorf("Children() returned %d, want 2", len(children))
		}
	})

	t.Run("SubstringExpression_with_length", func(t *testing.T) {
		node := SubstringExpression{Str: testIdent, Start: testExpr, Length: testExpr}
		children := node.Children()
		if len(children) != 3 {
			t.Errorf("Children() returned %d, want 3", len(children))
		}
	})

	t.Run("SubstringExpression_without_length", func(t *testing.T) {
		node := SubstringExpression{Str: testIdent, Start: testExpr}
		children := node.Children()
		if len(children) != 2 {
			t.Errorf("Children() returned %d, want 2", len(children))
		}
	})

	t.Run("OnConflict", func(t *testing.T) {
		node := OnConflict{
			Target: []Expression{testIdent},
			Action: OnConflictAction{
				DoUpdate: []UpdateExpression{{Column: testIdent, Value: testExpr}},
			},
		}
		children := node.Children()
		if len(children) != 2 {
			t.Errorf("Children() returned %d, want 2", len(children))
		}
	})

	t.Run("UpsertClause", func(t *testing.T) {
		node := UpsertClause{
			Updates: []UpdateExpression{{Column: testIdent, Value: testExpr}},
		}
		children := node.Children()
		if len(children) != 1 {
			t.Errorf("Children() returned %d, want 1", len(children))
		}
	})

	t.Run("Values", func(t *testing.T) {
		node := Values{
			Rows: [][]Expression{{testExpr, testExpr}, {testExpr}},
		}
		children := node.Children()
		if len(children) != 3 {
			t.Errorf("Children() returned %d, want 3", len(children))
		}
	})

	t.Run("ColumnDef", func(t *testing.T) {
		node := ColumnDef{
			Constraints: []ColumnConstraint{{Type: "NOT NULL"}, {Type: "UNIQUE"}},
		}
		children := node.Children()
		if len(children) != 2 {
			t.Errorf("Children() returned %d, want 2", len(children))
		}
	})

	t.Run("ColumnConstraint", func(t *testing.T) {
		node := ColumnConstraint{
			Default:    testExpr,
			References: &ReferenceDefinition{},
			Check:      testExpr,
		}
		children := node.Children()
		if len(children) != 3 {
			t.Errorf("Children() returned %d, want 3", len(children))
		}
	})

	t.Run("TableConstraint", func(t *testing.T) {
		node := TableConstraint{
			References: &ReferenceDefinition{},
			Check:      testExpr,
		}
		children := node.Children()
		if len(children) != 2 {
			t.Errorf("Children() returned %d, want 2", len(children))
		}
	})

	t.Run("ReferenceDefinition", func(t *testing.T) {
		node := ReferenceDefinition{}
		children := node.Children()
		if children != nil {
			t.Errorf("Children() should be nil for ReferenceDefinition")
		}
	})

	t.Run("PartitionBy", func(t *testing.T) {
		node := PartitionBy{Boundary: []Expression{testExpr}}
		children := node.Children()
		if len(children) != 1 {
			t.Errorf("Children() returned %d, want 1", len(children))
		}
	})

	t.Run("TableOption", func(t *testing.T) {
		node := TableOption{}
		children := node.Children()
		if children != nil {
			t.Errorf("Children() should be nil for TableOption")
		}
	})

	t.Run("UpdateExpression", func(t *testing.T) {
		node := UpdateExpression{Column: testIdent, Value: testExpr}
		children := node.Children()
		if len(children) != 2 {
			t.Errorf("Children() returned %d, want 2", len(children))
		}
	})

	t.Run("AlterTableAction", func(t *testing.T) {
		node := AlterTableAction{
			ColumnDef:  &ColumnDef{},
			Constraint: &TableConstraint{},
		}
		children := node.Children()
		if len(children) != 2 {
			t.Errorf("Children() returned %d, want 2", len(children))
		}
	})

	t.Run("IndexColumn", func(t *testing.T) {
		node := IndexColumn{}
		children := node.Children()
		if children != nil {
			t.Errorf("Children() should be nil for IndexColumn")
		}
	})

	t.Run("MergeWhenClause", func(t *testing.T) {
		node := MergeWhenClause{
			Condition: testExpr,
			Action:    &MergeAction{},
		}
		children := node.Children()
		if len(children) != 2 {
			t.Errorf("Children() returned %d, want 2", len(children))
		}
	})

	t.Run("MergeAction", func(t *testing.T) {
		node := MergeAction{
			SetClauses: []SetClause{{Column: "name", Value: testExpr}},
			Values:     []Expression{testExpr},
		}
		children := node.Children()
		if len(children) != 2 {
			t.Errorf("Children() returned %d, want 2", len(children))
		}
	})

	t.Run("SetClause_with_value", func(t *testing.T) {
		node := SetClause{Value: testExpr}
		children := node.Children()
		if len(children) != 1 {
			t.Errorf("Children() returned %d, want 1", len(children))
		}
	})

	t.Run("SetClause_without_value", func(t *testing.T) {
		node := SetClause{}
		children := node.Children()
		if children != nil {
			t.Errorf("Children() should be nil when Value is nil")
		}
	})

	t.Run("PartitionDefinition", func(t *testing.T) {
		node := PartitionDefinition{
			Values:   []Expression{testExpr},
			LessThan: testExpr,
			From:     testExpr,
			To:       testExpr,
			InValues: []Expression{testExpr, testExpr},
		}
		children := node.Children()
		if len(children) != 6 {
			t.Errorf("Children() returned %d, want 6", len(children))
		}
	})

	t.Run("DropStatement", func(t *testing.T) {
		node := DropStatement{}
		children := node.Children()
		if children != nil {
			t.Errorf("Children() should be nil for DropStatement")
		}
	})

	t.Run("TruncateStatement", func(t *testing.T) {
		node := TruncateStatement{}
		children := node.Children()
		if children != nil {
			t.Errorf("Children() should be nil for TruncateStatement")
		}
	})

	t.Run("RefreshMaterializedViewStatement", func(t *testing.T) {
		node := RefreshMaterializedViewStatement{}
		children := node.Children()
		if children != nil {
			t.Errorf("Children() should be nil for RefreshMaterializedViewStatement")
		}
	})

	t.Run("CreateViewStatement_with_query", func(t *testing.T) {
		node := CreateViewStatement{Query: testStmt}
		children := node.Children()
		if len(children) != 1 {
			t.Errorf("Children() returned %d, want 1", len(children))
		}
	})

	t.Run("CreateViewStatement_without_query", func(t *testing.T) {
		node := CreateViewStatement{}
		children := node.Children()
		if children != nil {
			t.Errorf("Children() should be nil when Query is nil")
		}
	})

	t.Run("CreateMaterializedViewStatement_with_query", func(t *testing.T) {
		node := CreateMaterializedViewStatement{Query: testStmt}
		children := node.Children()
		if len(children) != 1 {
			t.Errorf("Children() returned %d, want 1", len(children))
		}
	})

	t.Run("CreateMaterializedViewStatement_without_query", func(t *testing.T) {
		node := CreateMaterializedViewStatement{}
		children := node.Children()
		if children != nil {
			t.Errorf("Children() should be nil when Query is nil")
		}
	})

	t.Run("AST", func(t *testing.T) {
		node := AST{Statements: []Statement{testStmt, testStmt}}
		children := node.Children()
		if len(children) != 2 {
			t.Errorf("Children() returned %d, want 2", len(children))
		}
	})
}

// TestSelectStatementChildren tests comprehensive SelectStatement.Children()
func TestSelectStatementChildren(t *testing.T) {
	testIdent := &Identifier{Name: "test"}
	testExpr := &LiteralValue{Value: 1}

	t.Run("full_select", func(t *testing.T) {
		stmt := &SelectStatement{
			With:    &WithClause{},
			Columns: []Expression{testIdent},
			From:    []TableReference{{Name: "users"}},
			Joins:   []JoinClause{{Type: "INNER"}},
			Where:   testExpr,
			GroupBy: []Expression{testIdent},
			Having:  testExpr,
			Windows: []WindowSpec{{Name: "w"}},
			OrderBy: []OrderByExpression{{Expression: testIdent}},
			Fetch:   &FetchClause{},
		}
		children := stmt.Children()
		// With + 1 column + 1 from + 1 join + where + 1 groupby + having + 1 window + 1 orderby + fetch = 10
		if len(children) != 10 {
			t.Errorf("Children() returned %d, want 10", len(children))
		}
	})

	t.Run("minimal_select", func(t *testing.T) {
		stmt := &SelectStatement{
			Columns: []Expression{testIdent},
		}
		children := stmt.Children()
		if len(children) != 1 {
			t.Errorf("Children() returned %d, want 1", len(children))
		}
	})
}

// TestInsertStatementChildren tests InsertStatement.Children()
func TestInsertStatementChildren(t *testing.T) {
	testIdent := &Identifier{Name: "test"}
	testExpr := &LiteralValue{Value: 1}

	t.Run("full_insert", func(t *testing.T) {
		stmt := &InsertStatement{
			With:       &WithClause{},
			Columns:    []Expression{testIdent},
			Values:     [][]Expression{{testExpr}},
			Query:      &SelectStatement{},
			Returning:  []Expression{testIdent},
			OnConflict: &OnConflict{},
		}
		children := stmt.Children()
		// With + 1 column + 1 value + query + 1 returning + onconflict = 6
		if len(children) != 6 {
			t.Errorf("Children() returned %d, want 6", len(children))
		}
	})
}

// TestUpdateStatementChildren tests UpdateStatement.Children()
func TestUpdateStatementChildren(t *testing.T) {
	testIdent := &Identifier{Name: "test"}
	testExpr := &LiteralValue{Value: 1}

	t.Run("full_update", func(t *testing.T) {
		stmt := &UpdateStatement{
			With:        &WithClause{},
			Updates:     []UpdateExpression{{Column: testIdent, Value: testExpr}},
			Assignments: []UpdateExpression{{Column: testIdent, Value: testExpr}},
			From:        []TableReference{{Name: "users"}},
			Where:       testExpr,
			Returning:   []Expression{testIdent},
		}
		children := stmt.Children()
		// With + 1 update + 1 assignment + 1 from + where + 1 returning = 6
		if len(children) != 6 {
			t.Errorf("Children() returned %d, want 6", len(children))
		}
	})
}

// TestDeleteStatementChildren tests DeleteStatement.Children()
func TestDeleteStatementChildren(t *testing.T) {
	testIdent := &Identifier{Name: "test"}
	testExpr := &LiteralValue{Value: 1}

	t.Run("full_delete", func(t *testing.T) {
		stmt := &DeleteStatement{
			With:      &WithClause{},
			Using:     []TableReference{{Name: "users"}},
			Where:     testExpr,
			Returning: []Expression{testIdent},
		}
		children := stmt.Children()
		// With + 1 using + where + 1 returning = 4
		if len(children) != 4 {
			t.Errorf("Children() returned %d, want 4", len(children))
		}
	})
}

// TestCreateTableStatementChildren tests CreateTableStatement.Children()
func TestCreateTableStatementChildren(t *testing.T) {
	t.Run("full_create_table", func(t *testing.T) {
		stmt := &CreateTableStatement{
			Columns:     []ColumnDef{{Name: "id"}, {Name: "name"}},
			Constraints: []TableConstraint{{Type: "PRIMARY KEY"}},
			PartitionBy: &PartitionBy{},
			Partitions:  []PartitionDefinition{{Name: "p0"}},
		}
		children := stmt.Children()
		// 2 columns + 1 constraint + partition_by + 1 partition = 5
		if len(children) != 5 {
			t.Errorf("Children() returned %d, want 5", len(children))
		}
	})
}

// TestAlterTableStatementChildren tests AlterTableStatement.Children()
func TestAlterTableStatementChildren(t *testing.T) {
	t.Run("alter_table", func(t *testing.T) {
		stmt := &AlterTableStatement{
			Actions: []AlterTableAction{
				{Type: "ADD COLUMN"},
				{Type: "DROP COLUMN"},
			},
		}
		children := stmt.Children()
		if len(children) != 2 {
			t.Errorf("Children() returned %d, want 2", len(children))
		}
	})
}

// TestCreateIndexStatementChildren tests CreateIndexStatement.Children()
func TestCreateIndexStatementChildren(t *testing.T) {
	testExpr := &LiteralValue{Value: 1}

	t.Run("with_where", func(t *testing.T) {
		stmt := &CreateIndexStatement{
			Columns: []IndexColumn{{Column: "id"}, {Column: "name"}},
			Where:   testExpr,
		}
		children := stmt.Children()
		// 2 columns + where = 3
		if len(children) != 3 {
			t.Errorf("Children() returned %d, want 3", len(children))
		}
	})

	t.Run("without_where", func(t *testing.T) {
		stmt := &CreateIndexStatement{
			Columns: []IndexColumn{{Column: "id"}},
		}
		children := stmt.Children()
		if len(children) != 1 {
			t.Errorf("Children() returned %d, want 1", len(children))
		}
	})
}

// TestMergeStatementChildren tests MergeStatement.Children()
func TestMergeStatementChildren(t *testing.T) {
	testExpr := &LiteralValue{Value: 1}

	t.Run("full_merge", func(t *testing.T) {
		stmt := &MergeStatement{
			TargetTable: TableReference{Name: "target"},
			SourceTable: TableReference{Name: "source"},
			OnCondition: testExpr,
			WhenClauses: []*MergeWhenClause{
				{Type: "MATCHED"},
				{Type: "NOT_MATCHED"},
			},
		}
		children := stmt.Children()
		// target + source + condition + 2 when clauses = 5
		if len(children) != 5 {
			t.Errorf("Children() returned %d, want 5", len(children))
		}
	})
}

// TestBinaryExpressionWithCustomOp tests BinaryExpression.TokenLiteral() with custom operator
func TestBinaryExpressionWithCustomOp(t *testing.T) {
	customOp := &CustomBinaryOperator{
		Parts: []string{"pg_catalog", "->"},
	}
	expr := &BinaryExpression{
		CustomOp: customOp,
	}
	expected := "OPERATOR(pg_catalog.->)"
	if expr.TokenLiteral() != expected {
		t.Errorf("TokenLiteral() = %q, want %q", expr.TokenLiteral(), expected)
	}
}

// TestUnaryExpressionTokenLiteral tests UnaryExpression.TokenLiteral()
func TestUnaryExpressionTokenLiteral(t *testing.T) {
	tests := []struct {
		op       UnaryOperator
		expected string
	}{
		{Not, "NOT"},
		{Minus, "-"},
		{Plus, "+"},
		{PGBitwiseNot, "~"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			expr := &UnaryExpression{Operator: tt.op}
			if expr.TokenLiteral() != tt.expected {
				t.Errorf("TokenLiteral() = %q, want %q", expr.TokenLiteral(), tt.expected)
			}
		})
	}
}

// TestAlterStatementInterface tests AlterStatement interface methods
func TestAlterStatementInterface(t *testing.T) {
	testExpr := &LiteralValue{Value: 1}

	t.Run("AlterStatement_statementNode", func(t *testing.T) {
		stmt := &AlterStatement{}
		stmt.statementNode()
	})

	t.Run("AlterStatement_TokenLiteral", func(t *testing.T) {
		stmt := AlterStatement{}
		if stmt.TokenLiteral() != "ALTER" {
			t.Errorf("TokenLiteral() = %q, want \"ALTER\"", stmt.TokenLiteral())
		}
	})

	t.Run("AlterStatement_Children_with_operation", func(t *testing.T) {
		stmt := AlterStatement{
			Operation: &AlterTableOperation{},
		}
		children := stmt.Children()
		if len(children) != 1 {
			t.Errorf("Children() = %d, want 1", len(children))
		}
	})

	t.Run("AlterStatement_Children_without_operation", func(t *testing.T) {
		stmt := AlterStatement{}
		children := stmt.Children()
		if children != nil {
			t.Errorf("Children() should be nil")
		}
	})

	t.Run("AlterTableOperation", func(t *testing.T) {
		op := &AlterTableOperation{}
		op.alterOperationNode()
		if op.TokenLiteral() != "ALTER TABLE" {
			t.Errorf("TokenLiteral() = %q, want \"ALTER TABLE\"", op.TokenLiteral())
		}
	})

	t.Run("AlterTableOperation_Children", func(t *testing.T) {
		op := AlterTableOperation{
			ColumnDef:  &ColumnDef{Name: "id"},
			Constraint: &TableConstraint{},
		}
		children := op.Children()
		if len(children) != 2 {
			t.Errorf("Children() = %d, want 2", len(children))
		}
	})

	t.Run("AlterRoleOperation", func(t *testing.T) {
		op := &AlterRoleOperation{}
		op.alterOperationNode()
		if op.TokenLiteral() != "ALTER ROLE" {
			t.Errorf("TokenLiteral() = %q, want \"ALTER ROLE\"", op.TokenLiteral())
		}
	})

	t.Run("AlterRoleOperation_Children", func(t *testing.T) {
		op := AlterRoleOperation{
			ConfigValue: testExpr,
		}
		children := op.Children()
		if len(children) != 1 {
			t.Errorf("Children() = %d, want 1", len(children))
		}
	})

	t.Run("AlterPolicyOperation", func(t *testing.T) {
		op := &AlterPolicyOperation{}
		op.alterOperationNode()
		if op.TokenLiteral() != "ALTER POLICY" {
			t.Errorf("TokenLiteral() = %q, want \"ALTER POLICY\"", op.TokenLiteral())
		}
	})

	t.Run("AlterPolicyOperation_Children", func(t *testing.T) {
		op := AlterPolicyOperation{
			Using:     testExpr,
			WithCheck: testExpr,
		}
		children := op.Children()
		if len(children) != 2 {
			t.Errorf("Children() = %d, want 2", len(children))
		}
	})

	t.Run("AlterConnectorOperation", func(t *testing.T) {
		op := &AlterConnectorOperation{}
		op.alterOperationNode()
		if op.TokenLiteral() != "ALTER CONNECTOR" {
			t.Errorf("TokenLiteral() = %q, want \"ALTER CONNECTOR\"", op.TokenLiteral())
		}
		children := op.Children()
		if children != nil {
			t.Errorf("Children() should be nil")
		}
	})
}

// TestBinaryOperatorString tests BinaryOperator.String() for various operators
func TestBinaryOperatorString(t *testing.T) {
	tests := []struct {
		op       BinaryOperator
		expected string
	}{
		{BinaryPlus, "+"},
		{BinaryMinus, "-"},
		{Multiply, "*"},
		{Divide, "/"},
		{Modulo, "%"},
		{StringConcat, "||"},
		{Gt, ">"},
		{Lt, "<"},
		{GtEq, ">="},
		{LtEq, "<="},
		{Spaceship, "<=>"},
		{Eq, "="},
		{NotEq, "<>"},
		{And, "AND"},
		{Or, "OR"},
		{Xor, "XOR"},
		{BitwiseOr, "|"},
		{BitwiseAnd, "&"},
		{BitwiseXor, "^"},
		{Arrow, "->"},
		{LongArrow, "->>"},
		{Overlaps, "OVERLAPS"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if tt.op.String() != tt.expected {
				t.Errorf("String() = %q, want %q", tt.op.String(), tt.expected)
			}
		})
	}
}

// TestIndexTypeString tests IndexType.String()
func TestIndexTypeString(t *testing.T) {
	tests := []struct {
		idx      IndexType
		expected string
	}{
		{BTree, "BTREE"},
		{Hash, "HASH"},
		{IndexType(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if tt.idx.String() != tt.expected {
				t.Errorf("String() = %q, want %q", tt.idx.String(), tt.expected)
			}
		})
	}
}

// TestNullsDistinctOptionString tests NullsDistinctOption.String()
func TestNullsDistinctOptionString(t *testing.T) {
	tests := []struct {
		opt      NullsDistinctOption
		expected string
	}{
		{NullsDistinctNone, ""},
		{NullsDistinct, "NULLS DISTINCT"},
		{NullsNotDistinct, "NULLS NOT DISTINCT"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if tt.opt.String() != tt.expected {
				t.Errorf("String() = %q, want %q", tt.opt.String(), tt.expected)
			}
		})
	}
}

// TestIndexOptionString tests IndexOption.String()
func TestIndexOptionString(t *testing.T) {
	btree := BTree

	t.Run("UsingIndex", func(t *testing.T) {
		opt := &IndexOption{Type: UsingIndex, Using: &btree}
		expected := "USING BTREE"
		if opt.String() != expected {
			t.Errorf("String() = %q, want %q", opt.String(), expected)
		}
	})

	t.Run("CommentIndex", func(t *testing.T) {
		opt := &IndexOption{Type: CommentIndex, Comment: "test comment"}
		expected := "COMMENT 'test comment'"
		if opt.String() != expected {
			t.Errorf("String() = %q, want %q", opt.String(), expected)
		}
	})

	t.Run("Unknown", func(t *testing.T) {
		opt := &IndexOption{Type: IndexOptionType(99)}
		if opt.String() != "" {
			t.Errorf("String() = %q, want empty", opt.String())
		}
	})
}
