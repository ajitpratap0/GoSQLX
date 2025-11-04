package ast

import "testing"

// Test InsertStatement pool
func TestInsertStatementPool(t *testing.T) {
	t.Run("Get and Put", func(t *testing.T) {
		// Get from pool
		stmt := GetInsertStatement()
		if stmt == nil {
			t.Fatal("GetInsertStatement() returned nil")
		}

		// Use it
		stmt.TableName = "users"
		stmt.Columns = []Expression{
			&Identifier{Name: "name"},
			&Identifier{Name: "email"},
		}
		stmt.Values = []Expression{
			&LiteralValue{Value: "John"},
			&LiteralValue{Value: "john@example.com"},
		}

		// Return to pool
		PutInsertStatement(stmt)

		// Verify it was cleaned
		if stmt.TableName != "" {
			t.Errorf("TableName not cleared, got %v", stmt.TableName)
		}
		if len(stmt.Columns) != 0 {
			t.Errorf("Columns not cleared, len = %d", len(stmt.Columns))
		}
		if len(stmt.Values) != 0 {
			t.Errorf("Values not cleared, len = %d", len(stmt.Values))
		}
	})

	t.Run("Put nil statement", func(t *testing.T) {
		// Should not panic
		PutInsertStatement(nil)
	})
}

// Test UpdateStatement pool
func TestUpdateStatementPool(t *testing.T) {
	t.Run("Get and Put", func(t *testing.T) {
		// Get from pool
		stmt := GetUpdateStatement()
		if stmt == nil {
			t.Fatal("GetUpdateStatement() returned nil")
		}

		// Use it
		stmt.TableName = "users"
		stmt.Updates = []UpdateExpression{
			{
				Column: &Identifier{Name: "email"},
				Value:  &LiteralValue{Value: "new@example.com"},
			},
		}
		stmt.Where = &BinaryExpression{
			Left:     &Identifier{Name: "id"},
			Operator: "=",
			Right:    &LiteralValue{Value: "1"},
		}

		// Return to pool
		PutUpdateStatement(stmt)

		// Verify it was cleaned
		if stmt.TableName != "" {
			t.Errorf("TableName not cleared, got %v", stmt.TableName)
		}
		if len(stmt.Updates) != 0 {
			t.Errorf("Updates not cleared, len = %d", len(stmt.Updates))
		}
		if stmt.Where != nil {
			t.Errorf("Where not cleared, got %v", stmt.Where)
		}
	})

	t.Run("Put nil statement", func(t *testing.T) {
		// Should not panic
		PutUpdateStatement(nil)
	})
}

// Test DeleteStatement pool
func TestDeleteStatementPool(t *testing.T) {
	t.Run("Get and Put", func(t *testing.T) {
		// Get from pool
		stmt := GetDeleteStatement()
		if stmt == nil {
			t.Fatal("GetDeleteStatement() returned nil")
		}

		// Use it
		stmt.TableName = "users"
		stmt.Where = &BinaryExpression{
			Left:     &Identifier{Name: "id"},
			Operator: "=",
			Right:    &LiteralValue{Value: "10"},
		}

		// Return to pool
		PutDeleteStatement(stmt)

		// Verify it was cleaned
		if stmt.TableName != "" {
			t.Errorf("TableName not cleared, got %v", stmt.TableName)
		}
		if stmt.Where != nil {
			t.Errorf("Where not cleared, got %v", stmt.Where)
		}
	})

	t.Run("Put nil statement", func(t *testing.T) {
		// Should not panic
		PutDeleteStatement(nil)
	})
}

// Test UpdateExpression pool
func TestUpdateExpressionPool(t *testing.T) {
	t.Run("Get and Put", func(t *testing.T) {
		// Get from pool
		expr := GetUpdateExpression()
		if expr == nil {
			t.Fatal("GetUpdateExpression() returned nil")
		}

		// Use it
		expr.Column = &Identifier{Name: "status"}
		expr.Value = &LiteralValue{Value: "active"}

		// Return to pool
		PutUpdateExpression(expr)

		// Verify it was cleaned
		if expr.Column != nil {
			t.Errorf("Column not cleared, got %v", expr.Column)
		}
		if expr.Value != nil {
			t.Errorf("Value not cleared, got %v", expr.Value)
		}
	})

	t.Run("Put nil expression", func(t *testing.T) {
		// Should not panic
		PutUpdateExpression(nil)
	})
}

// Test LiteralValue pool
func TestLiteralValuePool(t *testing.T) {
	t.Run("Get and Put", func(t *testing.T) {
		// Get from pool
		lit := GetLiteralValue()
		if lit == nil {
			t.Fatal("GetLiteralValue() returned nil")
		}

		// Use it
		lit.Value = "test_value"

		// Return to pool
		PutLiteralValue(lit)

		// Verify it was cleaned
		if lit.Value != "" {
			t.Errorf("Value not cleared, got %v", lit.Value)
		}
	})

	t.Run("Put nil literal", func(t *testing.T) {
		// Should not panic
		PutLiteralValue(nil)
	})
}

// Test pool reuse
func TestPoolReuse(t *testing.T) {
	t.Run("InsertStatement reuse", func(t *testing.T) {
		// Get first statement
		stmt1 := GetInsertStatement()
		stmt1.TableName = "test"

		// Return it
		PutInsertStatement(stmt1)

		// Get another statement - might be the same one
		stmt2 := GetInsertStatement()
		if stmt2 == nil {
			t.Fatal("GetInsertStatement() returned nil on reuse")
		}

		// Should be clean
		if stmt2.TableName != "" {
			t.Errorf("Reused statement not clean, TableName = %v", stmt2.TableName)
		}

		PutInsertStatement(stmt2)
	})

	t.Run("LiteralValue reuse", func(t *testing.T) {
		// Get first literal
		lit1 := GetLiteralValue()
		lit1.Value = "first"

		// Return it
		PutLiteralValue(lit1)

		// Get another literal - might be the same one
		lit2 := GetLiteralValue()
		if lit2 == nil {
			t.Fatal("GetLiteralValue() returned nil on reuse")
		}

		// Should be clean
		if lit2.Value != "" {
			t.Errorf("Reused literal not clean, Value = %v", lit2.Value)
		}

		PutLiteralValue(lit2)
	})
}

// Test AST pool with NewAST and ReleaseAST
