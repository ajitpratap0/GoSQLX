package ast

import (
	"runtime"
	"testing"
	"time"
)

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
		// Values is now [][]Expression for multi-row support
		stmt.Values = [][]Expression{
			{
				&LiteralValue{Value: "John"},
				&LiteralValue{Value: "john@example.com"},
			},
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

		// Verify it was cleaned (Value is interface{}, should be nil)
		if lit.Value != nil {
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

		// Should be clean (Value is interface{}, so check for nil not empty string)
		if lit2.Value != nil {
			t.Errorf("Reused literal not clean, Value = %v", lit2.Value)
		}

		PutLiteralValue(lit2)
	})
}

// Memory leak detection tests for all pools
func TestMemoryLeaks_ASTPool(t *testing.T) {
	runtime.GC()
	runtime.GC()
	time.Sleep(10 * time.Millisecond)

	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	const iterations = 10000

	t.Logf("Running %d iterations of AST pool operations...", iterations)

	for i := 0; i < iterations; i++ {
		ast := NewAST()

		// Add statements
		ast.Statements = append(ast.Statements, &SelectStatement{
			TableName: "test",
			Columns:   []Expression{&Identifier{Name: "col1"}},
		})

		ReleaseAST(ast)

		if i%1000 == 0 && i > 0 {
			runtime.GC()
		}
	}

	runtime.GC()
	runtime.GC()
	time.Sleep(10 * time.Millisecond)

	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	allocDiff := int64(m2.Alloc) - int64(m1.Alloc)
	totalAllocDiff := int64(m2.TotalAlloc) - int64(m1.TotalAlloc)
	bytesPerOp := float64(totalAllocDiff) / float64(iterations)

	t.Logf("AST pool memory stats:")
	t.Logf("  Alloc diff: %d bytes", allocDiff)
	t.Logf("  TotalAlloc diff: %d bytes", totalAllocDiff)
	t.Logf("  Bytes per operation: %.2f", bytesPerOp)

	const maxAllocIncrease = 1024 * 1024 // 1MB
	const maxBytesPerOp = 5000           // 5KB

	if allocDiff > maxAllocIncrease {
		t.Errorf("Memory leak in AST pool: %d bytes (threshold: %d)", allocDiff, maxAllocIncrease)
	}

	if bytesPerOp > maxBytesPerOp {
		t.Errorf("High memory usage in AST pool: %.2f bytes/op (threshold: %d)", bytesPerOp, maxBytesPerOp)
	}

	if allocDiff <= maxAllocIncrease && bytesPerOp <= maxBytesPerOp {
		t.Logf("✅ AST pool memory leak test PASSED")
	}
}

func TestMemoryLeaks_SelectStatementPool(t *testing.T) {
	runtime.GC()
	runtime.GC()
	time.Sleep(10 * time.Millisecond)

	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	const iterations = 10000

	t.Logf("Running %d iterations of SelectStatement pool operations...", iterations)

	for i := 0; i < iterations; i++ {
		stmt := GetSelectStatement()

		stmt.TableName = "users"
		stmt.Columns = append(stmt.Columns, &Identifier{Name: "id"}, &Identifier{Name: "name"})
		stmt.Where = &BinaryExpression{
			Left:     &Identifier{Name: "active"},
			Operator: "=",
			Right:    &LiteralValue{Value: "true"},
		}

		PutSelectStatement(stmt)

		if i%1000 == 0 && i > 0 {
			runtime.GC()
		}
	}

	runtime.GC()
	runtime.GC()
	time.Sleep(10 * time.Millisecond)

	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	allocDiff := int64(m2.Alloc) - int64(m1.Alloc)
	totalAllocDiff := int64(m2.TotalAlloc) - int64(m1.TotalAlloc)
	bytesPerOp := float64(totalAllocDiff) / float64(iterations)

	t.Logf("SelectStatement pool memory stats:")
	t.Logf("  Alloc diff: %d bytes", allocDiff)
	t.Logf("  TotalAlloc diff: %d bytes", totalAllocDiff)
	t.Logf("  Bytes per operation: %.2f", bytesPerOp)

	const maxAllocIncrease = 1024 * 1024 // 1MB
	const maxBytesPerOp = 6000           // 6KB

	if allocDiff > maxAllocIncrease {
		t.Errorf("Memory leak in SelectStatement pool: %d bytes (threshold: %d)", allocDiff, maxAllocIncrease)
	}

	if bytesPerOp > maxBytesPerOp {
		t.Errorf("High memory usage in SelectStatement pool: %.2f bytes/op (threshold: %d)", bytesPerOp, maxBytesPerOp)
	}

	if allocDiff <= maxAllocIncrease && bytesPerOp <= maxBytesPerOp {
		t.Logf("✅ SelectStatement pool memory leak test PASSED")
	}
}

func TestMemoryLeaks_InsertStatementPool(t *testing.T) {
	runtime.GC()
	runtime.GC()
	time.Sleep(10 * time.Millisecond)

	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	const iterations = 10000

	t.Logf("Running %d iterations of InsertStatement pool operations...", iterations)

	for i := 0; i < iterations; i++ {
		stmt := GetInsertStatement()

		stmt.TableName = "users"
		stmt.Columns = append(stmt.Columns, &Identifier{Name: "name"}, &Identifier{Name: "email"})
		// Values is now [][]Expression for multi-row support
		stmt.Values = append(stmt.Values, []Expression{&LiteralValue{Value: "John"}, &LiteralValue{Value: "john@test.com"}})

		PutInsertStatement(stmt)

		if i%1000 == 0 && i > 0 {
			runtime.GC()
		}
	}

	runtime.GC()
	runtime.GC()
	time.Sleep(10 * time.Millisecond)

	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	allocDiff := int64(m2.Alloc) - int64(m1.Alloc)
	totalAllocDiff := int64(m2.TotalAlloc) - int64(m1.TotalAlloc)
	bytesPerOp := float64(totalAllocDiff) / float64(iterations)

	t.Logf("InsertStatement pool memory stats:")
	t.Logf("  Alloc diff: %d bytes", allocDiff)
	t.Logf("  TotalAlloc diff: %d bytes", totalAllocDiff)
	t.Logf("  Bytes per operation: %.2f", bytesPerOp)

	const maxAllocIncrease = 1024 * 1024 // 1MB
	const maxBytesPerOp = 6000           // 6KB

	if allocDiff > maxAllocIncrease {
		t.Errorf("Memory leak in InsertStatement pool: %d bytes (threshold: %d)", allocDiff, maxAllocIncrease)
	}

	if bytesPerOp > maxBytesPerOp {
		t.Errorf("High memory usage in InsertStatement pool: %.2f bytes/op (threshold: %d)", bytesPerOp, maxBytesPerOp)
	}

	if allocDiff <= maxAllocIncrease && bytesPerOp <= maxBytesPerOp {
		t.Logf("✅ InsertStatement pool memory leak test PASSED")
	}
}

func TestMemoryLeaks_UpdateStatementPool(t *testing.T) {
	runtime.GC()
	runtime.GC()
	time.Sleep(10 * time.Millisecond)

	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	const iterations = 10000

	t.Logf("Running %d iterations of UpdateStatement pool operations...", iterations)

	for i := 0; i < iterations; i++ {
		stmt := GetUpdateStatement()

		stmt.TableName = "users"
		stmt.Updates = append(stmt.Updates, UpdateExpression{
			Column: &Identifier{Name: "status"},
			Value:  &LiteralValue{Value: "active"},
		})
		stmt.Where = &BinaryExpression{
			Left:     &Identifier{Name: "id"},
			Operator: "=",
			Right:    &LiteralValue{Value: "123"},
		}

		PutUpdateStatement(stmt)

		if i%1000 == 0 && i > 0 {
			runtime.GC()
		}
	}

	runtime.GC()
	runtime.GC()
	time.Sleep(10 * time.Millisecond)

	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	allocDiff := int64(m2.Alloc) - int64(m1.Alloc)
	totalAllocDiff := int64(m2.TotalAlloc) - int64(m1.TotalAlloc)
	bytesPerOp := float64(totalAllocDiff) / float64(iterations)

	t.Logf("UpdateStatement pool memory stats:")
	t.Logf("  Alloc diff: %d bytes", allocDiff)
	t.Logf("  TotalAlloc diff: %d bytes", totalAllocDiff)
	t.Logf("  Bytes per operation: %.2f", bytesPerOp)

	const maxAllocIncrease = 1024 * 1024 // 1MB
	const maxBytesPerOp = 6000           // 6KB

	if allocDiff > maxAllocIncrease {
		t.Errorf("Memory leak in UpdateStatement pool: %d bytes (threshold: %d)", allocDiff, maxAllocIncrease)
	}

	if bytesPerOp > maxBytesPerOp {
		t.Errorf("High memory usage in UpdateStatement pool: %.2f bytes/op (threshold: %d)", bytesPerOp, maxBytesPerOp)
	}

	if allocDiff <= maxAllocIncrease && bytesPerOp <= maxBytesPerOp {
		t.Logf("✅ UpdateStatement pool memory leak test PASSED")
	}
}

func TestMemoryLeaks_DeleteStatementPool(t *testing.T) {
	runtime.GC()
	runtime.GC()
	time.Sleep(10 * time.Millisecond)

	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	const iterations = 10000

	t.Logf("Running %d iterations of DeleteStatement pool operations...", iterations)

	for i := 0; i < iterations; i++ {
		stmt := GetDeleteStatement()

		stmt.TableName = "users"
		stmt.Where = &BinaryExpression{
			Left:     &Identifier{Name: "id"},
			Operator: "=",
			Right:    &LiteralValue{Value: "999"},
		}

		PutDeleteStatement(stmt)

		if i%1000 == 0 && i > 0 {
			runtime.GC()
		}
	}

	runtime.GC()
	runtime.GC()
	time.Sleep(10 * time.Millisecond)

	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	allocDiff := int64(m2.Alloc) - int64(m1.Alloc)
	totalAllocDiff := int64(m2.TotalAlloc) - int64(m1.TotalAlloc)
	bytesPerOp := float64(totalAllocDiff) / float64(iterations)

	t.Logf("DeleteStatement pool memory stats:")
	t.Logf("  Alloc diff: %d bytes", allocDiff)
	t.Logf("  TotalAlloc diff: %d bytes", totalAllocDiff)
	t.Logf("  Bytes per operation: %.2f", bytesPerOp)

	const maxAllocIncrease = 1024 * 1024 // 1MB
	const maxBytesPerOp = 5000           // 5KB

	if allocDiff > maxAllocIncrease {
		t.Errorf("Memory leak in DeleteStatement pool: %d bytes (threshold: %d)", allocDiff, maxAllocIncrease)
	}

	if bytesPerOp > maxBytesPerOp {
		t.Errorf("High memory usage in DeleteStatement pool: %.2f bytes/op (threshold: %d)", bytesPerOp, maxBytesPerOp)
	}

	if allocDiff <= maxAllocIncrease && bytesPerOp <= maxBytesPerOp {
		t.Logf("✅ DeleteStatement pool memory leak test PASSED")
	}
}

func TestMemoryLeaks_IdentifierPool(t *testing.T) {
	runtime.GC()
	runtime.GC()
	time.Sleep(10 * time.Millisecond)

	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	const iterations = 10000

	t.Logf("Running %d iterations of Identifier pool operations...", iterations)

	for i := 0; i < iterations; i++ {
		ident := GetIdentifier()
		ident.Name = "test_column"
		PutIdentifier(ident)

		if i%1000 == 0 && i > 0 {
			runtime.GC()
		}
	}

	runtime.GC()
	runtime.GC()
	time.Sleep(10 * time.Millisecond)

	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	allocDiff := int64(m2.Alloc) - int64(m1.Alloc)
	totalAllocDiff := int64(m2.TotalAlloc) - int64(m1.TotalAlloc)
	bytesPerOp := float64(totalAllocDiff) / float64(iterations)

	t.Logf("Identifier pool memory stats:")
	t.Logf("  Alloc diff: %d bytes", allocDiff)
	t.Logf("  TotalAlloc diff: %d bytes", totalAllocDiff)
	t.Logf("  Bytes per operation: %.2f", bytesPerOp)

	const maxAllocIncrease = 512 * 1024 // 512KB
	const maxBytesPerOp = 3000          // 3KB

	if allocDiff > maxAllocIncrease {
		t.Errorf("Memory leak in Identifier pool: %d bytes (threshold: %d)", allocDiff, maxAllocIncrease)
	}

	if bytesPerOp > maxBytesPerOp {
		t.Errorf("High memory usage in Identifier pool: %.2f bytes/op (threshold: %d)", bytesPerOp, maxBytesPerOp)
	}

	if allocDiff <= maxAllocIncrease && bytesPerOp <= maxBytesPerOp {
		t.Logf("✅ Identifier pool memory leak test PASSED")
	}
}

func TestMemoryLeaks_BinaryExpressionPool(t *testing.T) {
	runtime.GC()
	runtime.GC()
	time.Sleep(10 * time.Millisecond)

	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	const iterations = 10000

	t.Logf("Running %d iterations of BinaryExpression pool operations...", iterations)

	for i := 0; i < iterations; i++ {
		expr := GetBinaryExpression()
		expr.Left = &Identifier{Name: "col"}
		expr.Operator = "="
		expr.Right = &LiteralValue{Value: "val"}
		PutBinaryExpression(expr)

		if i%1000 == 0 && i > 0 {
			runtime.GC()
		}
	}

	runtime.GC()
	runtime.GC()
	time.Sleep(10 * time.Millisecond)

	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	allocDiff := int64(m2.Alloc) - int64(m1.Alloc)
	totalAllocDiff := int64(m2.TotalAlloc) - int64(m1.TotalAlloc)
	bytesPerOp := float64(totalAllocDiff) / float64(iterations)

	t.Logf("BinaryExpression pool memory stats:")
	t.Logf("  Alloc diff: %d bytes", allocDiff)
	t.Logf("  TotalAlloc diff: %d bytes", totalAllocDiff)
	t.Logf("  Bytes per operation: %.2f", bytesPerOp)

	const maxAllocIncrease = 1024 * 1024 // 1MB
	const maxBytesPerOp = 5000           // 5KB

	if allocDiff > maxAllocIncrease {
		t.Errorf("Memory leak in BinaryExpression pool: %d bytes (threshold: %d)", allocDiff, maxAllocIncrease)
	}

	if bytesPerOp > maxBytesPerOp {
		t.Errorf("High memory usage in BinaryExpression pool: %.2f bytes/op (threshold: %d)", bytesPerOp, maxBytesPerOp)
	}

	if allocDiff <= maxAllocIncrease && bytesPerOp <= maxBytesPerOp {
		t.Logf("✅ BinaryExpression pool memory leak test PASSED")
	}
}

func TestMemoryLeaks_LiteralValuePool(t *testing.T) {
	runtime.GC()
	runtime.GC()
	time.Sleep(10 * time.Millisecond)

	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	const iterations = 10000

	t.Logf("Running %d iterations of LiteralValue pool operations...", iterations)

	for i := 0; i < iterations; i++ {
		lit := GetLiteralValue()
		lit.Value = "test_value"
		lit.Type = "STRING"
		PutLiteralValue(lit)

		if i%1000 == 0 && i > 0 {
			runtime.GC()
		}
	}

	runtime.GC()
	runtime.GC()
	time.Sleep(10 * time.Millisecond)

	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	allocDiff := int64(m2.Alloc) - int64(m1.Alloc)
	totalAllocDiff := int64(m2.TotalAlloc) - int64(m1.TotalAlloc)
	bytesPerOp := float64(totalAllocDiff) / float64(iterations)

	t.Logf("LiteralValue pool memory stats:")
	t.Logf("  Alloc diff: %d bytes", allocDiff)
	t.Logf("  TotalAlloc diff: %d bytes", totalAllocDiff)
	t.Logf("  Bytes per operation: %.2f", bytesPerOp)

	const maxAllocIncrease = 512 * 1024 // 512KB
	const maxBytesPerOp = 3000          // 3KB

	if allocDiff > maxAllocIncrease {
		t.Errorf("Memory leak in LiteralValue pool: %d bytes (threshold: %d)", allocDiff, maxAllocIncrease)
	}

	if bytesPerOp > maxBytesPerOp {
		t.Errorf("High memory usage in LiteralValue pool: %.2f bytes/op (threshold: %d)", bytesPerOp, maxBytesPerOp)
	}

	if allocDiff <= maxAllocIncrease && bytesPerOp <= maxBytesPerOp {
		t.Logf("✅ LiteralValue pool memory leak test PASSED")
	}
}
